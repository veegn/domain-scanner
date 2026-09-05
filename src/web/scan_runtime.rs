use super::models::{ScanStreamMessage, StartScanRequest, StreamHub, TaskControl, TaskSignal};
use super::scan_runtime_support::{
    COUNTER_PERSIST_INTERVAL, MAX_EXCEPTION_REPLAY_ROUNDS, STATUS_PUBLISH_INTERVAL,
    ScanRuntimeState, WORKER_DELAY_MS, flush_pending_results, flush_pending_state_logs,
    flush_scan_buffers, get_result_counts, initialize_scan_counters, load_persisted_retries,
    prepare_job_feeder, publish_scan_status, queue_event_log, rate_limited_service,
};
pub(super) use super::scan_runtime_support::{add_event_log, mark_scan_running};
use crate::checker::CheckerRegistry;
use crate::worker;
use async_channel::{Sender as JobSender, bounded};
use serde_json::json;
use sqlx::sqlite::SqlitePool;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Semaphore;
use tokio::sync::{broadcast, mpsc};
use tracing::error;

pub(super) async fn run_scan_logic(
    db: &SqlitePool,
    scan_id: &str,
    params: StartScanRequest,
    registry: Arc<CheckerRegistry>,
    task_control: TaskControl,
    streams: &StreamHub,
    workers_per_scan: usize,
    global_check_permits: Arc<Semaphore>,
) {
    let task_signal = task_control.register(scan_id);
    let scan_stream = streams.sender_for_scan(scan_id).await;
    mark_scan_running(db, streams, scan_id).await;

    let counts = get_result_counts(db, scan_id).await.unwrap_or((0, 0));
    let resume_processed = counts.0;
    let resume_found = counts.1;
    let _ = add_event_log(
        db,
        streams,
        scan_id,
        "INFO",
        "task.resume",
        None,
        None,
        vec![
            ("processed", json!(resume_processed)),
            ("found", json!(resume_found)),
        ],
    )
    .await;

    let (jobs_tx, jobs_rx) = bounded::<String>(1000);
    let feeder_done = Arc::new(AtomicBool::new(false));
    let feeder_error = Arc::new(Mutex::new(None));
    let pending_domains = Arc::new(AtomicUsize::new(0));

    let total = match prepare_job_feeder(
        db,
        streams,
        scan_id,
        &params,
        &jobs_tx,
        feeder_done.clone(),
        feeder_error.clone(),
        pending_domains.clone(),
        task_signal.clone(),
        task_control.clone(),
    )
    .await
    {
        Ok(total) => total,
        Err(()) => {
            streams.cleanup_scan(scan_id).await;
            task_control.unregister(scan_id);
            return;
        }
    };
    let mut jobs_tx = Some(jobs_tx);

    let _ = add_event_log(
        db,
        streams,
        scan_id,
        "INFO",
        "worker.pool",
        None,
        Some("Spawning worker threads".to_string()),
        vec![
            ("size", json!(workers_per_scan)),
            ("delay_ms", json!(WORKER_DELAY_MS)),
            ("total", json!(total)),
        ],
    )
    .await;

    if let Err(err) =
        initialize_scan_counters(db, scan_id, total, resume_processed, resume_found).await
    {
        let _ = add_event_log(
            db,
            streams,
            scan_id,
            "ERROR",
            "storage.counters_init_failed",
            None,
            Some("Failed to initialize scan counters".to_string()),
            vec![("error", json!(err.to_string()))],
        )
        .await;
        task_control.unregister(scan_id);
        return;
    }

    let mut state = ScanRuntimeState::new(resume_processed, resume_found);
    if let Err(err) = load_persisted_retries(db, scan_id, &mut state).await {
        let retry_at = now_epoch_seconds().saturating_add(30);
        let _ =
            sqlx::query("UPDATE scans SET status = 'pending', retry_not_before = ? WHERE id = ?")
                .bind(retry_at)
                .bind(scan_id)
                .execute(db)
                .await;
        let _ = add_event_log(
            db,
            streams,
            scan_id,
            "ERROR",
            "storage.retries_load_failed",
            None,
            Some("Failed to restore deferred retries".to_string()),
            vec![("error", json!(err.to_string()))],
        )
        .await;
        streams.cleanup_scan(scan_id).await;
        task_control.unregister(scan_id);
        return;
    }

    let (tx_results, mut rx_results) = mpsc::channel(100);
    let worker_throttle = Arc::new(worker::WorkerThrottle::new(
        Duration::from_millis(WORKER_DELAY_MS),
        workers_per_scan,
    ));

    for id in 1..=workers_per_scan {
        let jobs = jobs_rx.clone();
        let tx = tx_results.clone();
        let throttle = worker_throttle.clone();
        let reg = registry.clone();
        let signal_clone = task_signal.clone();
        let permits = global_check_permits.clone();
        tokio::spawn(async move {
            worker::worker(id, jobs, tx, throttle, reg, signal_clone, permits).await;
        });
    }
    drop(tx_results);

    streams.notify_scans();
    publish_scan_status(
        &scan_stream,
        scan_id,
        "running",
        total,
        state.processed,
        state.found,
        0,
    )
    .await;

    loop {
        if should_handle_drained_feeder(&feeder_done, &pending_domains) {
            handle_drained_feeder(
                db,
                &scan_stream,
                scan_id,
                total,
                &mut jobs_tx,
                &pending_domains,
                &mut state,
            )
            .await;
        }

        let msg = match tokio::time::timeout(Duration::from_millis(100), rx_results.recv()).await {
            Ok(Some(msg)) => msg,
            Ok(None) => break,
            Err(_) => {
                if TaskControl::signal(&task_signal) != TaskSignal::Run {
                    jobs_rx.close();
                    jobs_tx.take();
                }
                if feeder_done.load(Ordering::Relaxed)
                    && pending_domains.load(Ordering::Relaxed) == 0
                    && state.deferred_retries.is_empty()
                {
                    jobs_tx.take();
                }
                continue;
            }
        };

        if TaskControl::signal(&task_signal) != TaskSignal::Run {
            jobs_rx.close();
            jobs_tx.take();
            let _ = add_event_log(
                db,
                streams,
                scan_id,
                "WARN",
                "task.signal_changed",
                None,
                Some("Task signal changed from RUN; closing job queue".to_string()),
                vec![(
                    "signal",
                    json!(format!("{:?}", TaskControl::signal(&task_signal))),
                )],
            )
            .await;
        }

        match msg {
            crate::WorkerMessage::Scanning(domain) => {
                // SSE-only broadcast: scanning status notification without DB persistence
                let payload =
                    serde_json::json!({"event":"domain.scanning","domain":&domain}).to_string();
                let _ = scan_stream.send(crate::web::models::ScanStreamMessage::Log(
                    crate::web::models::ScanLogEvent {
                        id: 0,
                        message: payload,
                        level: "INFO".to_string(),
                        created_at: String::new(),
                    },
                ));
            }
            crate::WorkerMessage::Result(res) => {
                if !res.trace.is_empty() {
                    let _ = queue_event_log(
                        &mut state.pending_log_flush,
                        db,
                        &scan_stream,
                        scan_id,
                        "INFO",
                        "domain.trace",
                        Some(res.domain.as_str()),
                        None,
                        vec![("steps", json!(res.trace))],
                    )
                    .await;
                }

                pending_domains.fetch_sub(1, Ordering::Relaxed);

                if res.retryable {
                    handle_retryable_result(
                        db,
                        &scan_stream,
                        scan_id,
                        &worker_throttle,
                        &mut state,
                        res,
                        total,
                    )
                    .await;
                    continue;
                }

                handle_completed_result(
                    db,
                    &scan_stream,
                    scan_id,
                    total,
                    &task_signal,
                    &mut state,
                    res,
                )
                .await;

                if feeder_done.load(Ordering::Relaxed)
                    && pending_domains.load(Ordering::Relaxed) == 0
                    && state.deferred_retries.is_empty()
                {
                    jobs_tx.take();
                }
            }
        }
    }

    let feeder_failure = feeder_error
        .lock()
        .expect("feeder error mutex poisoned")
        .take();
    if let Some(feeder_failure) = feeder_failure {
        let _ = sqlx::query("DELETE FROM scan_retries WHERE scan_id = ?")
            .bind(scan_id)
            .execute(db)
            .await;
        if let Err(err) = flush_scan_buffers(db, streams, &scan_stream, scan_id, &mut state).await {
            transition_after_storage_failure(
                db,
                streams,
                &scan_stream,
                scan_id,
                total,
                TaskSignal::Run,
                &state,
                &err,
            )
            .await;
        } else {
            let _ = add_event_log(
                db,
                streams,
                scan_id,
                "ERROR",
                "feeder.failed",
                None,
                Some("Failed to restore the scan input stream".to_string()),
                vec![("error", json!(feeder_failure))],
            )
            .await;
            let _ = sqlx::query(
                "UPDATE scans SET status = 'failed', processed = ?, found = ?, finished_at = CURRENT_TIMESTAMP WHERE id = ?",
            )
            .bind(state.processed)
            .bind(state.found)
            .bind(scan_id)
            .execute(db)
            .await;
            publish_scan_status(
                &scan_stream,
                scan_id,
                "failed",
                total,
                state.processed,
                state.found,
                0,
            )
            .await;
            streams.notify_scans();
        }
        let _ = scan_stream.send(ScanStreamMessage::Complete(scan_id.to_string()));
        streams.cleanup_scan(scan_id).await;
        task_control.unregister(scan_id);
        return;
    }

    let final_signal = TaskControl::signal(&task_signal);
    if final_signal == TaskSignal::Run {
        queue_exhausted_retries(db, &scan_stream, scan_id, total, &mut state).await;
    } else if final_signal == TaskSignal::Cancel {
        let _ = sqlx::query("DELETE FROM scan_retries WHERE scan_id = ?")
            .bind(scan_id)
            .execute(db)
            .await;
    }
    if let Err(err) = flush_scan_buffers(db, streams, &scan_stream, scan_id, &mut state).await {
        transition_after_storage_failure(
            db,
            streams,
            &scan_stream,
            scan_id,
            total,
            TaskControl::signal(&task_signal),
            &state,
            &err,
        )
        .await;
        let _ = scan_stream.send(ScanStreamMessage::Complete(scan_id.to_string()));
        streams.cleanup_scan(scan_id).await;
        task_control.unregister(scan_id);
        return;
    }

    let signal = TaskControl::signal(&task_signal);
    let (status, log_event, log_msg, log_fields) = match signal {
        TaskSignal::Cancel => (
            "cancelled",
            "task.cancelled",
            "Scan cancelled",
            vec![
                ("processed", json!(state.processed)),
                ("found", json!(state.found)),
            ],
        ),
        TaskSignal::Pause => (
            "paused",
            "task.paused",
            "Scan paused",
            vec![
                ("processed", json!(state.processed)),
                ("found", json!(state.found)),
            ],
        ),
        TaskSignal::Run => (
            "finished",
            "task.summary",
            "Scan completed",
            vec![
                ("processed", json!(state.processed)),
                ("registration_record_absent", json!(state.found)),
            ],
        ),
    };

    let _ = queue_event_log(
        &mut state.pending_log_flush,
        db,
        &scan_stream,
        scan_id,
        if signal == TaskSignal::Run {
            "INFO"
        } else {
            "WARN"
        },
        log_event,
        None,
        Some(log_msg.to_string()),
        log_fields,
    )
    .await;

    flush_pending_state_logs(db, &scan_stream, scan_id, &mut state).await;

    let final_total = if signal == TaskSignal::Run {
        state.processed
    } else {
        total
    };
    let stmt = match signal {
        TaskSignal::Cancel => {
            "UPDATE scans SET status = 'cancelled', total = ?, processed = ?, found = ?, finished_at = CURRENT_TIMESTAMP WHERE id = ?"
        }
        TaskSignal::Pause => {
            "UPDATE scans SET status = 'paused', total = ?, processed = ?, found = ?, retry_not_before = NULL WHERE id = ?"
        }
        TaskSignal::Run => {
            "UPDATE scans SET status = 'finished', total = ?, processed = ?, found = ?, retry_not_before = NULL, finished_at = CURRENT_TIMESTAMP WHERE id = ?"
        }
    };
    if let Err(err) = sqlx::query(stmt)
        .bind(final_total)
        .bind(state.processed)
        .bind(state.found)
        .bind(scan_id)
        .execute(db)
        .await
    {
        error!(target: "domain_scanner::queue", context = "task_status", scan_id = %scan_id, status, error = %err, "failed to mark task {}", status);
        if signal != TaskSignal::Cancel {
            let _ = add_event_log(
                db,
                streams,
                scan_id,
                "ERROR",
                "task.status_update_failed",
                None,
                Some(format!("Failed to mark task {}", status)),
                vec![("error", json!(err.to_string())), ("status", json!(status))],
            )
            .await;
        }
    }

    publish_scan_status(
        &scan_stream,
        scan_id,
        status,
        final_total,
        state.processed,
        state.found,
        0,
    )
    .await;
    streams.notify_scans();
    let _ = scan_stream.send(ScanStreamMessage::Complete(scan_id.to_string()));
    streams.cleanup_scan(scan_id).await;

    task_control.unregister(scan_id);
}

fn should_handle_drained_feeder(feeder_done: &AtomicBool, pending_domains: &AtomicUsize) -> bool {
    feeder_done.load(Ordering::Relaxed) && pending_domains.load(Ordering::Relaxed) == 0
}

fn now_epoch_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

async fn handle_drained_feeder(
    db: &SqlitePool,
    scan_stream: &broadcast::Sender<ScanStreamMessage>,
    scan_id: &str,
    total: i64,
    jobs_tx: &mut Option<JobSender<String>>,
    pending_domains: &Arc<AtomicUsize>,
    state: &mut ScanRuntimeState,
) {
    if !state.deferred_retries.is_empty() {
        let now = Instant::now();
        let domains: Vec<String> = state
            .deferred_retries
            .keys()
            .filter(|domain| {
                state
                    .deferred_retry_ready_at
                    .get(*domain)
                    .map(|ready_at| *ready_at <= now)
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        if domains.is_empty() {
            return;
        }

        let mut scheduled = 0usize;
        if let Some(sender) = jobs_tx.as_ref() {
            for domain in domains {
                match sender.try_send(domain.clone()) {
                    Ok(()) => {
                        pending_domains.fetch_add(1, Ordering::Relaxed);
                        state.deferred_retries.remove(&domain);
                        state.deferred_retry_ready_at.remove(&domain);
                        scheduled += 1;
                    }
                    Err(async_channel::TrySendError::Full(_)) => break,
                    Err(async_channel::TrySendError::Closed(_)) => {
                        jobs_tx.take();
                        break;
                    }
                }
            }
        }

        if scheduled > 0 {
            let _ = queue_event_log(
                &mut state.pending_log_flush,
                db,
                scan_stream,
                scan_id,
                "WARN",
                "task.exception_replay_scheduled",
                None,
                Some("Scheduling deferred exception replay".to_string()),
                vec![("domains", json!(scheduled))],
            )
            .await;
        }

        state.last_published_deferred = state.deferred_count();
        publish_scan_status(
            scan_stream,
            scan_id,
            "running",
            total,
            state.processed,
            state.found,
            state.last_published_deferred,
        )
        .await;
    } else {
        jobs_tx.take();
    }
}

async fn handle_retryable_result(
    db: &SqlitePool,
    scan_stream: &broadcast::Sender<ScanStreamMessage>,
    scan_id: &str,
    worker_throttle: &Arc<worker::WorkerThrottle>,
    state: &mut ScanRuntimeState,
    res: crate::DomainResult,
    total: i64,
) {
    let limited_service = if res.rate_limited {
        rate_limited_service(&res)
    } else {
        None
    };

    if let Some(service) = limited_service {
        let paused_until = worker_throttle.pause_for(Duration::from_secs(60));
        let remaining_workers = worker_throttle.reduce_workers();
        let new_delay = if remaining_workers.is_none() {
            Some(worker_throttle.slow_down_by_percent(20))
        } else {
            None
        };
        let _ = queue_event_log(
            &mut state.pending_log_flush,
            db,
            scan_stream,
            scan_id,
            "WARN",
            "task.throttle_adjusted",
            Some(res.domain.as_str()),
            Some(match remaining_workers {
                Some(_) => {
                    "Rate limit detected; pausing task and reducing worker concurrency".to_string()
                }
                None => "Rate limit detected; pausing task and reducing scan speed".to_string(),
            }),
            {
                let mut fields = vec![
                    ("source", json!(service)),
                    ("pause_secs", json!(60)),
                    ("paused_until_epoch_ms", json!(paused_until)),
                    ("active_workers", json!(worker_throttle.current_workers())),
                ];
                if let Some(delay) = new_delay {
                    fields.push(("delay_ms", json!(delay.as_millis() as u64)));
                }
                fields
            },
        )
        .await;
    }

    let reason = res
        .error
        .clone()
        .unwrap_or_else(|| "transient failure".to_string());
    let next_attempt = state.retry_attempts.get(&res.domain).copied().unwrap_or(0) + 1;
    if next_attempt > MAX_EXCEPTION_REPLAY_ROUNDS {
        state.retry_attempts.remove(&res.domain);
        state.deferred_retry_ready_at.remove(&res.domain);
        state.deferred_retries.remove(&res.domain);
        state.processed += 1;
        let _ = queue_event_log(
            &mut state.pending_log_flush,
            db,
            scan_stream,
            scan_id,
            "ERROR",
            "domain.retry_exhausted",
            Some(res.domain.as_str()),
            Some(reason),
            vec![("replay_rounds", json!(MAX_EXCEPTION_REPLAY_ROUNDS))],
        )
        .await;
        state
            .pending_result_flush
            .push(super::scan_runtime_support::PendingResultPersist {
                domain: res.domain,
                registration_record_absent: false,
                purchasable: None,
                expiration_date: None,
                signatures: String::new(),
            });
        flush_retry_terminal_results_if_needed(db, scan_stream, scan_id, state).await;
        return;
    }

    let _ = queue_event_log(
        &mut state.pending_log_flush,
        db,
        scan_stream,
        scan_id,
        if res.rate_limited { "WARN" } else { "INFO" },
        "domain.deferred_retry_recorded",
        Some(res.domain.as_str()),
        Some(reason),
        vec![
            ("replay_round", json!(next_attempt)),
            ("rate_limited", json!(res.rate_limited)),
            ("retry_after_secs", json!(res.retry_after_secs.unwrap_or(0))),
            ("source", json!(limited_service.unwrap_or("unknown"))),
        ],
    )
    .await;

    let retry_after_secs = res.retry_after_secs.unwrap_or(0).min(24 * 60 * 60);
    let ready_at = Instant::now() + Duration::from_secs(retry_after_secs);
    let next_retry_at = now_epoch_seconds().saturating_add(retry_after_secs as i64);
    if let Err(err) = sqlx::query(
        "INSERT INTO scan_retries
            (scan_id, domain, attempt, next_retry_at, error, rate_limited, retry_after_secs)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(scan_id, domain) DO UPDATE SET
            attempt = excluded.attempt,
            next_retry_at = excluded.next_retry_at,
            error = excluded.error,
            rate_limited = excluded.rate_limited,
            retry_after_secs = excluded.retry_after_secs",
    )
    .bind(scan_id)
    .bind(&res.domain)
    .bind(next_attempt as i64)
    .bind(next_retry_at)
    .bind(&res.error)
    .bind(res.rate_limited)
    .bind(retry_after_secs as i64)
    .execute(db)
    .await
    {
        error!(target: "domain_scanner::queue", context = "storage", scan_id = %scan_id,
            domain = %res.domain, error = %err, "failed to persist deferred retry");
        let _ = queue_event_log(
            &mut state.pending_log_flush,
            db,
            scan_stream,
            scan_id,
            "ERROR",
            "storage.retry_persist_failed",
            Some(res.domain.as_str()),
            Some("Could not persist retry state; recording an inconclusive result".to_string()),
            vec![("error", json!(err.to_string()))],
        )
        .await;
        state.processed += 1;
        state
            .pending_result_flush
            .push(super::scan_runtime_support::PendingResultPersist {
                domain: res.domain,
                registration_record_absent: false,
                purchasable: None,
                expiration_date: None,
                signatures: String::new(),
            });
        flush_retry_terminal_results_if_needed(db, scan_stream, scan_id, state).await;
        return;
    }
    state
        .retry_attempts
        .insert(res.domain.clone(), next_attempt);
    state
        .deferred_retry_ready_at
        .insert(res.domain.clone(), ready_at);
    state.deferred_retries.insert(res.domain.clone(), res);
    let deferred = state.deferred_count();
    if deferred != state.last_published_deferred {
        state.last_published_deferred = deferred;
        publish_scan_status(
            scan_stream,
            scan_id,
            "running",
            total,
            state.processed,
            state.found,
            deferred,
        )
        .await;
    }
}

async fn flush_retry_terminal_results_if_needed(
    db: &SqlitePool,
    scan_stream: &broadcast::Sender<ScanStreamMessage>,
    scan_id: &str,
    state: &mut ScanRuntimeState,
) {
    if state.pending_result_flush.len() < super::scan_runtime_support::RESULT_FLUSH_BATCH_SIZE {
        return;
    }
    if let Err(err) =
        flush_pending_results(db, scan_stream, scan_id, &mut state.pending_result_flush).await
    {
        error!(
            target: "domain_scanner::queue",
            context = "storage",
            scan_id = %scan_id,
            error = %err,
            pending = state.pending_result_flush.len(),
            "failed to flush terminal retry results; retaining them for finalization"
        );
    }
}

async fn handle_completed_result(
    db: &SqlitePool,
    scan_stream: &broadcast::Sender<ScanStreamMessage>,
    scan_id: &str,
    total: i64,
    task_signal: &Arc<AtomicU8>,
    state: &mut ScanRuntimeState,
    res: crate::DomainResult,
) {
    state.processed += 1;

    if res.registration_record_absent {
        state.found += 1;
        let _ = queue_event_log(
            &mut state.pending_log_flush,
            db,
            scan_stream,
            scan_id,
            "INFO",
            "domain.no_registration_record",
            Some(res.domain.as_str()),
            None,
            vec![],
        )
        .await;
    } else if let Some(err) = res.error {
        let _ = queue_event_log(
            &mut state.pending_log_flush,
            db,
            scan_stream,
            scan_id,
            "WARN",
            "domain.error",
            Some(res.domain.as_str()),
            Some(err),
            vec![],
        )
        .await;
    } else if !res.signatures.is_empty() {
        let mut fields = vec![("signatures", json!(res.signatures))];
        if let Some(expiration_date) = &res.expiration_date {
            fields.push(("expiration_date", json!(expiration_date)));
        }
        let _ = queue_event_log(
            &mut state.pending_log_flush,
            db,
            scan_stream,
            scan_id,
            "INFO",
            "domain.registered",
            Some(res.domain.as_str()),
            None,
            fields,
        )
        .await;
    } else {
        let _ = queue_event_log(
            &mut state.pending_log_flush,
            db,
            scan_stream,
            scan_id,
            "WARN",
            "domain.registration_status_unknown",
            Some(res.domain.as_str()),
            None,
            vec![],
        )
        .await;
    }

    state
        .pending_result_flush
        .push(super::scan_runtime_support::PendingResultPersist {
            domain: res.domain.clone(),
            registration_record_absent: res.registration_record_absent,
            purchasable: res.purchasable,
            expiration_date: res.expiration_date.clone(),
            signatures: res.signatures.join(","),
        });

    if state.pending_result_flush.len() >= super::scan_runtime_support::RESULT_FLUSH_BATCH_SIZE
        && let Err(err) =
            flush_pending_results(db, scan_stream, scan_id, &mut state.pending_result_flush).await
    {
        error!(
            target: "domain_scanner::queue",
            context = "storage",
            scan_id = %scan_id,
            error = %err,
            pending = state.pending_result_flush.len(),
            "continuing scan with the failed result batch retained in memory"
        );
    }

    persist_scan_progress_if_needed(db, scan_stream, scan_id, task_signal, state).await;
    publish_running_status_if_needed(scan_stream, scan_id, total, task_signal, state).await;
}

async fn persist_scan_progress_if_needed(
    db: &SqlitePool,
    scan_stream: &broadcast::Sender<ScanStreamMessage>,
    scan_id: &str,
    task_signal: &Arc<AtomicU8>,
    state: &mut ScanRuntimeState,
) {
    if state.processed - state.last_persisted < COUNTER_PERSIST_INTERVAL
        && TaskControl::signal(task_signal) == TaskSignal::Run
    {
        return;
    }

    match sqlx::query("UPDATE scans SET processed = ?, found = ? WHERE id = ?")
        .bind(state.processed)
        .bind(state.found)
        .bind(scan_id)
        .execute(db)
        .await
    {
        Ok(_) => state.last_persisted = state.processed,
        Err(err) => {
            error!(
                target: "domain_scanner::queue",
                context = "storage",
                scan_id = %scan_id,
                processed = state.processed,
                found = state.found,
                error = %err,
                "failed to persist counters"
            );
            let _ = queue_event_log(
                &mut state.pending_log_flush,
                db,
                scan_stream,
                scan_id,
                "ERROR",
                "storage.counters_persist_failed",
                None,
                Some("Failed to persist counters".to_string()),
                vec![
                    ("processed", json!(state.processed)),
                    ("found", json!(state.found)),
                    ("error", json!(err.to_string())),
                ],
            )
            .await;
        }
    }
}

async fn publish_running_status_if_needed(
    scan_stream: &broadcast::Sender<ScanStreamMessage>,
    scan_id: &str,
    total: i64,
    task_signal: &Arc<AtomicU8>,
    state: &mut ScanRuntimeState,
) {
    let deferred = state.deferred_count();
    let should_publish_status = (state.processed - state.last_status_published)
        >= STATUS_PUBLISH_INTERVAL
        || deferred != state.last_published_deferred
        || TaskControl::signal(task_signal) != TaskSignal::Run;

    if should_publish_status {
        state.last_status_published = state.processed;
        state.last_published_deferred = deferred;
        publish_scan_status(
            scan_stream,
            scan_id,
            "running",
            total,
            state.processed,
            state.found,
            deferred,
        )
        .await;
    }
}

async fn queue_exhausted_retries(
    db: &SqlitePool,
    scan_stream: &broadcast::Sender<ScanStreamMessage>,
    scan_id: &str,
    total: i64,
    state: &mut ScanRuntimeState,
) {
    if state.deferred_retries.is_empty() {
        return;
    }

    state.deferred_retry_ready_at.clear();
    state.retry_attempts.clear();
    let exhausted: Vec<crate::DomainResult> =
        state.deferred_retries.drain().map(|(_, res)| res).collect();

    for res in &exhausted {
        state.processed += 1;
        let _ = queue_event_log(
            &mut state.pending_log_flush,
            db,
            scan_stream,
            scan_id,
            "ERROR",
            "domain.retry_exhausted",
            Some(res.domain.as_str()),
            Some(
                res.error
                    .as_deref()
                    .unwrap_or("transient failure")
                    .to_string(),
            ),
            vec![("replay_rounds", json!(MAX_EXCEPTION_REPLAY_ROUNDS))],
        )
        .await;
    }

    for res in exhausted {
        state
            .pending_result_flush
            .push(super::scan_runtime_support::PendingResultPersist {
                domain: res.domain,
                registration_record_absent: false,
                purchasable: None,
                expiration_date: None,
                signatures: String::new(),
            });
    }

    flush_pending_state_logs(db, scan_stream, scan_id, state).await;
    publish_scan_status(
        scan_stream,
        scan_id,
        "running",
        total,
        state.processed,
        state.found,
        0,
    )
    .await;
}

async fn transition_after_storage_failure(
    db: &SqlitePool,
    streams: &StreamHub,
    scan_stream: &broadcast::Sender<ScanStreamMessage>,
    scan_id: &str,
    total: i64,
    signal: TaskSignal,
    state: &ScanRuntimeState,
    error: &sqlx::Error,
) {
    let (status, retry_not_before) = match signal {
        TaskSignal::Run => (
            "pending",
            Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64
                    + 30,
            ),
        ),
        TaskSignal::Pause => ("paused", None),
        TaskSignal::Cancel => ("cancelled", None),
    };
    let (persisted_processed, persisted_found) =
        get_result_counts(db, scan_id).await.unwrap_or((0, 0));

    error!(
        target: "domain_scanner::queue",
        context = "storage",
        scan_id = %scan_id,
        error = %error,
        buffered_results = state.pending_result_flush.len(),
        next_status = status,
        "scan finalization stopped because result persistence did not complete"
    );

    if let Err(status_error) = sqlx::query(
        "UPDATE scans
         SET status = ?, processed = ?, found = ?, retry_not_before = ?,
             finished_at = CASE WHEN ? = 'cancelled' THEN CURRENT_TIMESTAMP ELSE NULL END
         WHERE id = ?",
    )
    .bind(status)
    .bind(persisted_processed)
    .bind(persisted_found)
    .bind(retry_not_before)
    .bind(status)
    .bind(scan_id)
    .execute(db)
    .await
    {
        error!(
            target: "domain_scanner::queue",
            context = "storage",
            scan_id = %scan_id,
            error = %status_error,
            "failed to place scan into a recoverable state after storage failure"
        );
    }

    publish_scan_status(
        scan_stream,
        scan_id,
        status,
        total,
        persisted_processed,
        persisted_found,
        0,
    )
    .await;
    streams.notify_scans();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn retry_replay_never_blocks_the_result_consumer_on_a_full_queue() {
        let db = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let (scan_stream, _) = broadcast::channel(8);
        let (jobs_tx, jobs_rx) = bounded(2);
        let mut jobs_tx = Some(jobs_tx);
        let pending_domains = Arc::new(AtomicUsize::new(0));
        let mut state = ScanRuntimeState::new(0, 0);

        for index in 0..5 {
            let domain = format!("retry-{index}.test");
            state
                .deferred_retry_ready_at
                .insert(domain.clone(), Instant::now());
            state.deferred_retries.insert(
                domain.clone(),
                crate::DomainResult {
                    domain,
                    registration_record_absent: false,
                    purchasable: None,
                    error: Some("temporary".to_string()),
                    signatures: Vec::new(),
                    expiration_date: None,
                    rate_limited: false,
                    retryable: true,
                    retry_after_secs: None,
                    trace: Vec::new(),
                },
            );
        }

        tokio::time::timeout(
            Duration::from_millis(100),
            handle_drained_feeder(
                &db,
                &scan_stream,
                "scan-1",
                5,
                &mut jobs_tx,
                &pending_domains,
                &mut state,
            ),
        )
        .await
        .expect("retry scheduling must not await queue capacity");

        assert_eq!(jobs_rx.len(), 2);
        assert_eq!(pending_domains.load(Ordering::Relaxed), 2);
        assert_eq!(state.deferred_retries.len(), 3);
    }
}
