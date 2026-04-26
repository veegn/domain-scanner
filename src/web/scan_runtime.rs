use super::models::{ScanStreamMessage, StartScanRequest, StreamHub, TaskControl, TaskSignal};
use super::scan_runtime_support::{
    COUNTER_PERSIST_INTERVAL, MAX_EXCEPTION_REPLAY_ROUNDS, STATUS_PUBLISH_INTERVAL,
    WORKER_COUNT, WORKER_DELAY_MS, ScanRuntimeState, flush_pending_results,
    flush_pending_state_logs, flush_scan_buffers, get_result_counts, initialize_scan_counters,
    is_whois_rate_limited, prepare_job_feeder, publish_scan_status, queue_event_log,
};
pub(super) use super::scan_runtime_support::{add_event_log, mark_scan_running};
use crate::checker::CheckerRegistry;
use crate::worker;
use async_channel::{Sender as JobSender, bounded};
use serde_json::json;
use sqlx::sqlite::SqlitePool;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tracing::error;

pub(super) async fn run_scan_logic(
    db: &SqlitePool,
    scan_id: &str,
    params: StartScanRequest,
    _skip_count: i64,
    _initial_found: i64,
    registry: Arc<CheckerRegistry>,
    task_control: TaskControl,
    streams: StreamHub,
) {
    let task_signal = task_control.register(scan_id);
    let scan_stream = streams.sender_for_scan(scan_id).await;
    mark_scan_running(db, &streams, scan_id).await;

    let counts = get_result_counts(db, scan_id).await.unwrap_or((0, 0));
    let resume_processed = counts.0;
    let resume_found = counts.1;
    let _ = add_event_log(
        db,
        &streams,
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
    let pending_domains = Arc::new(AtomicUsize::new(0));

    let total = match prepare_job_feeder(
        db,
        &streams,
        scan_id,
        &params,
        resume_processed,
        &jobs_tx,
        feeder_done.clone(),
        pending_domains.clone(),
        task_signal.clone(),
        task_control.clone(),
    )
    .await
    {
        Ok(total) => total,
        Err(()) => return,
    };
    let mut jobs_tx = Some(jobs_tx);

    let _ = add_event_log(
        db,
        &streams,
        scan_id,
        "INFO",
        "worker.pool",
        None,
        Some("Spawning worker threads".to_string()),
        vec![
            ("size", json!(WORKER_COUNT)),
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
            &streams,
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

    let (tx_results, mut rx_results) = mpsc::channel(100);
    let worker_throttle = Arc::new(worker::WorkerThrottle::new(
        Duration::from_millis(WORKER_DELAY_MS),
        WORKER_COUNT,
    ));

    for id in 1..=WORKER_COUNT {
        let jobs = jobs_rx.clone();
        let tx = tx_results.clone();
        let throttle = worker_throttle.clone();
        let reg = registry.clone();
        let signal_clone = task_signal.clone();
        tokio::spawn(async move {
            worker::worker(id, jobs, tx, throttle, reg, signal_clone).await;
        });
    }
    drop(tx_results);

    let mut state = ScanRuntimeState::new(resume_processed, resume_found);
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
                &streams,
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
                let _ = add_event_log(
                    db,
                    &streams,
                    scan_id,
                    "INFO",
                    "domain.scanning",
                    Some(domain.as_str()),
                    None,
                    vec![],
                )
                .await;
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
                    &streams,
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

    flush_scan_buffers(db, &streams, &scan_stream, scan_id, &mut state).await;
    persist_exhausted_retries(db, &scan_stream, scan_id, total, &mut state).await;

    match TaskControl::signal(&task_signal) {
        TaskSignal::Cancel => {
            let _ = queue_event_log(
                &mut state.pending_log_flush,
                db,
                &scan_stream,
                scan_id,
                "WARN",
                "task.cancelled",
                None,
                Some("Scan cancelled".to_string()),
                vec![
                    ("processed", json!(state.processed)),
                    ("found", json!(state.found)),
                ],
            )
            .await;
            flush_pending_state_logs(db, &scan_stream, scan_id, &mut state).await;
            if let Err(err) = sqlx::query(
                "UPDATE scans SET status = 'cancelled', processed = ?, found = ?, finished_at = CURRENT_TIMESTAMP WHERE id = ?",
            )
            .bind(state.processed)
            .bind(state.found)
            .bind(scan_id)
            .execute(db)
            .await
            {
                error!(
                    target: "domain_scanner::queue",
                    context = "task_status",
                    scan_id = %scan_id,
                    status = "cancelled",
                    error = %err,
                    "failed to mark task cancelled"
                );
            }
            publish_scan_status(
                &scan_stream,
                scan_id,
                "cancelled",
                total,
                state.processed,
                state.found,
                0,
            )
            .await;
            streams.notify_scans();
            let _ = scan_stream.send(ScanStreamMessage::Complete(scan_id.to_string()));
            streams.cleanup_scan(scan_id).await;
        }
        TaskSignal::Pause => {
            let _ = queue_event_log(
                &mut state.pending_log_flush,
                db,
                &scan_stream,
                scan_id,
                "WARN",
                "task.paused",
                None,
                Some("Scan paused".to_string()),
                vec![
                    ("processed", json!(state.processed)),
                    ("found", json!(state.found)),
                ],
            )
            .await;
            flush_pending_state_logs(db, &scan_stream, scan_id, &mut state).await;

            if let Err(err) = sqlx::query(
                "UPDATE scans
                 SET status = 'paused', processed = ?, found = ?, retry_not_before = NULL
                 WHERE id = ?",
            )
            .bind(state.processed)
            .bind(state.found)
            .bind(scan_id)
            .execute(db)
            .await
            {
                error!(
                    target: "domain_scanner::queue",
                    context = "task_status",
                    scan_id = %scan_id,
                    status = "paused",
                    error = %err,
                    "failed to mark task paused"
                );
                let _ = add_event_log(
                    db,
                    &streams,
                    scan_id,
                    "ERROR",
                    "task.status_update_failed",
                    None,
                    Some("Failed to mark task paused".to_string()),
                    vec![
                        ("error", json!(err.to_string())),
                        ("status", json!("paused")),
                    ],
                )
                .await;
            }

            publish_scan_status(
                &scan_stream,
                scan_id,
                "paused",
                total,
                state.processed,
                state.found,
                0,
            )
            .await;
            streams.notify_scans();
            let _ = scan_stream.send(ScanStreamMessage::Complete(scan_id.to_string()));
            streams.cleanup_scan(scan_id).await;
        }
        TaskSignal::Run => {
            let _ = queue_event_log(
                &mut state.pending_log_flush,
                db,
                &scan_stream,
                scan_id,
                "INFO",
                "task.summary",
                None,
                Some("Scan completed".to_string()),
                vec![
                    ("processed", json!(state.processed)),
                    ("available", json!(state.found)),
                ],
            )
            .await;
            flush_pending_state_logs(db, &scan_stream, scan_id, &mut state).await;
            if let Err(err) = sqlx::query(
                "UPDATE scans
                 SET status = 'finished', processed = ?, found = ?, retry_not_before = NULL, finished_at = CURRENT_TIMESTAMP
                 WHERE id = ?",
            )
            .bind(state.processed)
            .bind(state.found)
            .bind(scan_id)
            .execute(db)
            .await
            {
                error!(
                    target: "domain_scanner::queue",
                    context = "task_status",
                    scan_id = %scan_id,
                    status = "finished",
                    error = %err,
                    "failed to mark task finished"
                );
                let _ = add_event_log(
                    db,
                    &streams,
                    scan_id,
                    "ERROR",
                    "task.status_update_failed",
                    None,
                    Some("Failed to mark task finished".to_string()),
                    vec![("error", json!(err.to_string())), ("status", json!("finished"))],
                )
                .await;
            }
            publish_scan_status(
                &scan_stream,
                scan_id,
                "finished",
                total,
                state.processed,
                state.found,
                0,
            )
            .await;
            streams.notify_scans();
            let _ = scan_stream.send(ScanStreamMessage::Complete(scan_id.to_string()));
            streams.cleanup_scan(scan_id).await;
        }
    }

    task_control.unregister(scan_id);
}

fn should_handle_drained_feeder(
    feeder_done: &AtomicBool,
    pending_domains: &AtomicUsize,
) -> bool {
    feeder_done.load(Ordering::Relaxed) && pending_domains.load(Ordering::Relaxed) == 0
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
    if !state.deferred_retries.is_empty() && state.replay_round < MAX_EXCEPTION_REPLAY_ROUNDS {
        state.replay_round += 1;
        let replay_count = state.deferred_retries.len();
        let domains: Vec<String> = state.deferred_retries.keys().cloned().collect();
        state.deferred_retries.clear();

        let _ = queue_event_log(
            &mut state.pending_log_flush,
            db,
            scan_stream,
            scan_id,
            "WARN",
            "task.exception_replay_scheduled",
            None,
            Some("Scheduling deferred exception replay".to_string()),
            vec![
                ("round", json!(state.replay_round)),
                ("domains", json!(replay_count)),
            ],
        )
        .await;

        if let Some(sender) = jobs_tx.as_ref() {
            for domain in domains {
                pending_domains.fetch_add(1, Ordering::Relaxed);
                if sender.send(domain).await.is_err() {
                    pending_domains.fetch_sub(1, Ordering::Relaxed);
                    break;
                }
            }
        }

        state.last_published_deferred = replay_count as i64;
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
    if res.rate_limited && is_whois_rate_limited(&res) {
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
                    "WHOIS rate limit detected; pausing task and reducing worker concurrency"
                        .to_string()
                }
                None => "WHOIS rate limit detected; pausing task and reducing scan speed".to_string(),
            }),
            {
                let mut fields = vec![
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
            ("replay_round", json!(state.replay_round + 1)),
            ("rate_limited", json!(res.rate_limited)),
            ("retry_after_secs", json!(res.retry_after_secs.unwrap_or(0))),
        ],
    )
    .await;

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

async fn handle_completed_result(
    db: &SqlitePool,
    streams: &StreamHub,
    scan_stream: &broadcast::Sender<ScanStreamMessage>,
    scan_id: &str,
    total: i64,
    task_signal: &Arc<AtomicU8>,
    state: &mut ScanRuntimeState,
    res: crate::DomainResult,
) {
    state.processed += 1;

    if res.available {
        state.found += 1;
        let _ = queue_event_log(
            &mut state.pending_log_flush,
            db,
            scan_stream,
            scan_id,
            "INFO",
            "domain.available",
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
    } else {
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
    }

    state
        .pending_result_flush
        .push(super::scan_runtime_support::PendingResultPersist {
            domain: res.domain.clone(),
            available: res.available,
            expiration_date: res.expiration_date.clone(),
            signatures: res.signatures.join(","),
        });

    if state.pending_result_flush.len()
        >= super::scan_runtime_support::RESULT_FLUSH_BATCH_SIZE
    {
        flush_pending_results(
            db,
            streams,
            scan_stream,
            scan_id,
            &mut state.pending_result_flush,
        )
        .await;
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

    if let Err(err) = sqlx::query("UPDATE scans SET processed = ?, found = ? WHERE id = ?")
        .bind(state.processed)
        .bind(state.found)
        .bind(scan_id)
        .execute(db)
        .await
    {
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
    state.last_persisted = state.processed;
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

async fn persist_exhausted_retries(
    db: &SqlitePool,
    scan_stream: &broadcast::Sender<ScanStreamMessage>,
    scan_id: &str,
    total: i64,
    state: &mut ScanRuntimeState,
) {
    if state.deferred_retries.is_empty() {
        return;
    }

    for (_, res) in state.deferred_retries.drain() {
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

        match sqlx::query_as::<_, crate::web::models::ScanResultEvent>(
            "INSERT OR REPLACE INTO results (scan_id, domain, available, expiration_date, signatures)
             VALUES (?, ?, 0, NULL, '')
             RETURNING rowid as event_id, domain, available, expiration_date, signatures",
        )
        .bind(scan_id)
        .bind(&res.domain)
        .fetch_one(db)
        .await
        {
            Ok(row) => {
                let _ = scan_stream.send(ScanStreamMessage::Result(row));
            }
            Err(err) => {
                error!(
                    target: "domain_scanner::queue",
                    context = "storage",
                    scan_id = %scan_id,
                    domain = %res.domain,
                    error = %err,
                    "failed to persist exhausted exception result"
                );
            }
        }
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
