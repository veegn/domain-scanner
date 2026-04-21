use super::models::{
    ScanLogEvent, ScanResultEvent, ScanStatus, ScanStreamMessage, StartScanRequest, StreamHub,
    TaskControl, TaskSignal,
};
use crate::checker::CheckerRegistry;
use crate::generator;
use crate::worker;
use serde::Serialize;
use serde_json::{Map, Value, json};
use sqlx::{Row, sqlite::SqlitePool};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, error, info, warn};

const MAX_EXCEPTION_REPLAY_ROUNDS: u32 = 3;
const WORKER_COUNT: usize = 10;
const WORKER_DELAY_MS: u64 = 500;

#[derive(Serialize)]
struct ScanLogRecord {
    event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Map::is_empty")]
    fields: Map<String, Value>,
}

struct PendingScanTask {
    scan_id: String,
    params: StartScanRequest,
    processed: i64,
    found: i64,
}

/// The single task background worker.
pub async fn start_task_worker(
    db: SqlitePool,
    mut rx: mpsc::Receiver<()>,
    task_control: TaskControl,
    registry: Arc<CheckerRegistry>,
    streams: StreamHub,
) {
    info!(
        target: "domain_scanner::queue",
        context = "worker",
        "background task worker started"
    );

    loop {
        let next_task = fetch_next_ready_task(&db).await;

        if let Some(row) = next_task {
            let task = PendingScanTask::from_row(row);
            let scan_id = task.scan_id.clone();
            let params = &task.params;

            info!(
                target: "domain_scanner::queue",
                context = "task_start",
                scan_id = %scan_id,
                "starting task"
            );
            let _ = add_event_log(
                &db,
                &streams,
                &scan_id,
                "INFO",
                "task.picked",
                None,
                Some("Task picked up by background worker".to_string()),
                vec![],
            )
            .await;
            let _ = add_event_log(
                &db,
                &streams,
                &scan_id,
                "INFO",
                "task.config",
                None,
                None,
                vec![
                    ("length", json!(params.length)),
                    ("suffix", json!(params.suffix)),
                    ("pattern", json!(params.pattern)),
                    ("regex", json!(params.regex.as_deref().unwrap_or("-"))),
                    (
                        "source",
                        json!(if params.domains.is_some() {
                            "manual-list"
                        } else {
                            "generated"
                        }),
                    ),
                ],
            )
            .await;

            mark_scan_running(&db, &streams, &scan_id).await;

            run_scan_logic(
                &db,
                &scan_id,
                task.params,
                task.processed,
                task.found,
                registry.clone(),
                task_control.clone(),
                streams.clone(),
            )
            .await;

            info!(
                target: "domain_scanner::queue",
                context = "task_finish",
                scan_id = %scan_id,
                "task processing loop exited"
            );
            continue;
        }

        let next_retry_at = get_next_retry_not_before(&db).await.unwrap_or(None);
        if let Some(retry_at) = next_retry_at {
            let wait_secs = retry_at.saturating_sub(now_epoch_seconds()).max(1) as u64;
            debug!(
                target: "domain_scanner::queue",
                context = "scheduler",
                wait_secs,
                "no ready tasks; sleeping until next retry window"
            );
            match tokio::time::timeout(Duration::from_secs(wait_secs), rx.recv()).await {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => {}
            }
        } else if rx.recv().await.is_none() {
            break;
        }
    }
}

impl PendingScanTask {
    fn from_row(row: sqlx::sqlite::SqliteRow) -> Self {
        let scan_id: String = row.try_get("id").unwrap_or_default();
        let priority_words_json: String = row
            .try_get("priority_words")
            .unwrap_or_else(|_| "null".to_string());
        let domains_json: String = row
            .try_get("domains")
            .unwrap_or_else(|_| "null".to_string());

        Self {
            scan_id,
            params: StartScanRequest {
                length: row.try_get::<i64, _>("length").unwrap_or(0) as usize,
                suffix: row.try_get("suffix").unwrap_or_default(),
                pattern: row.try_get("pattern").unwrap_or_default(),
                regex: row.try_get("regex").unwrap_or(None),
                priority_words: serde_json::from_str(&priority_words_json).unwrap_or(None),
                domains: serde_json::from_str(&domains_json).unwrap_or(None),
            },
            processed: row.try_get("processed").unwrap_or(0),
            found: row.try_get("found").unwrap_or(0),
        }
    }
}

async fn fetch_next_ready_task(db: &SqlitePool) -> Option<sqlx::sqlite::SqliteRow> {
    match sqlx::query(
        "
        SELECT s.id, s.length, s.suffix, s.pattern, s.regex, s.processed, s.found,
               p.priority_words, p.domains
        FROM scans s
        LEFT JOIN scan_payloads p ON s.id = p.scan_id
        WHERE s.status IN ('pending', 'running')
          AND (s.retry_not_before IS NULL OR s.retry_not_before <= ?)
        ORDER BY s.priority DESC, s.created_at ASC LIMIT 1
    ",
    )
    .bind(now_epoch_seconds())
    .fetch_optional(db)
    .await
    {
        Ok(row) => row,
        Err(e) => {
            error!(
                target: "domain_scanner::queue",
                context = "scheduler",
                error = %e,
                "failed to query next task"
            );
            None
        }
    }
}

async fn run_scan_logic(
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

    let (jobs_tx, jobs_rx) = mpsc::channel(1000);
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
    let jobs_rx = Arc::new(Mutex::new(jobs_rx));

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
        initialize_scan_counters(db, &streams, scan_id, total, resume_processed, resume_found).await
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

    let mut processed = resume_processed;
    let mut found = resume_found;
    let mut last_persisted = processed;
    let mut deferred_retries: HashMap<String, crate::DomainResult> = HashMap::new();
    let mut replay_round = 0_u32;
    streams.notify_scans();
    publish_scan_status(&streams, scan_id, "running", total, processed, found, 0).await;

    loop {
        if feeder_done.load(Ordering::Relaxed) && pending_domains.load(Ordering::Relaxed) == 0 {
            if !deferred_retries.is_empty() && replay_round < MAX_EXCEPTION_REPLAY_ROUNDS {
                replay_round += 1;
                let replay_count = deferred_retries.len();
                let domains: Vec<String> = deferred_retries.keys().cloned().collect();
                deferred_retries.clear();

                let _ = add_event_log(
                    db,
                    &streams,
                    scan_id,
                    "WARN",
                    "task.exception_replay_scheduled",
                    None,
                    Some("Scheduling deferred exception replay".to_string()),
                    vec![
                        ("round", json!(replay_round)),
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
            } else {
                jobs_tx.take();
            }
        }

        let msg = match tokio::time::timeout(Duration::from_millis(100), rx_results.recv()).await {
            Ok(Some(msg)) => msg,
            Ok(None) => break,
            Err(_) => {
                if feeder_done.load(Ordering::Relaxed)
                    && pending_domains.load(Ordering::Relaxed) == 0
                    && deferred_retries.is_empty()
                {
                    jobs_tx.take();
                }
                continue;
            }
        };

        if TaskControl::signal(&task_signal) != TaskSignal::Run {
            let mut jobs = jobs_rx.lock().await;
            jobs.close();
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
                    let _ = add_event_log(
                        db,
                        &streams,
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
                    if res.rate_limited && is_whois_rate_limited(&res) {
                        let paused_until = worker_throttle.pause_for(Duration::from_secs(60));
                        let remaining_workers = worker_throttle.reduce_workers();
                        let new_delay = if remaining_workers.is_none() {
                            Some(worker_throttle.slow_down_by_percent(20))
                        } else {
                            None
                        };
                        let _ = add_event_log(
                            db,
                            &streams,
                            scan_id,
                            "WARN",
                            "task.throttle_adjusted",
                            Some(res.domain.as_str()),
                            Some(match remaining_workers {
                                Some(_) => {
                                    "WHOIS rate limit detected; pausing task and reducing worker concurrency"
                                        .to_string()
                                }
                                None => {
                                    "WHOIS rate limit detected; pausing task and reducing scan speed"
                                        .to_string()
                                }
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
                    let _ = add_event_log(
                        db,
                        &streams,
                        scan_id,
                        if res.rate_limited { "WARN" } else { "INFO" },
                        "domain.deferred_retry_recorded",
                        Some(res.domain.as_str()),
                        Some(reason),
                        vec![
                            ("replay_round", json!(replay_round + 1)),
                            ("rate_limited", json!(res.rate_limited)),
                            ("retry_after_secs", json!(res.retry_after_secs.unwrap_or(0))),
                        ],
                    )
                    .await;

                    deferred_retries.insert(res.domain.clone(), res);
                    continue;
                }

                processed += 1;

                if res.available {
                    found += 1;
                    let _ = add_event_log(
                        db,
                        &streams,
                        scan_id,
                        "INFO",
                        "domain.available",
                        Some(res.domain.as_str()),
                        None,
                        vec![],
                    )
                    .await;
                } else if let Some(err) = res.error {
                    let _ = add_event_log(
                        db,
                        &streams,
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
                    let _ = add_event_log(
                        db,
                        &streams,
                        scan_id,
                        "INFO",
                        "domain.registered",
                        Some(res.domain.as_str()),
                        None,
                        fields,
                    )
                    .await;
                }

                let result_signatures = res.signatures.join(",");
                let inserted_result = sqlx::query_as::<_, ScanResultEvent>(
                    "INSERT OR REPLACE INTO results (scan_id, domain, available, expiration_date, signatures)
                     VALUES (?, ?, ?, ?, ?)
                     RETURNING rowid as event_id, domain, available, expiration_date, signatures",
                )
                .bind(scan_id)
                .bind(&res.domain)
                .bind(res.available)
                .bind(&res.expiration_date)
                .bind(&result_signatures)
                .fetch_one(db)
                .await;

                if let Err(err) = inserted_result.as_ref() {
                    error!(
                        target: "domain_scanner::queue",
                        context = "storage",
                        scan_id = %scan_id,
                        domain = %res.domain,
                        error = %err,
                        "failed to persist result"
                    );
                    let _ = add_event_log(
                        db,
                        &streams,
                        scan_id,
                        "ERROR",
                        "storage.result_persist_failed",
                        Some(res.domain.as_str()),
                        Some("Failed to persist result".to_string()),
                        vec![("error", json!(err.to_string()))],
                    )
                    .await;
                }

                if res.available {
                    if let Ok(result_event) = inserted_result {
                        streams
                            .publish_scan(scan_id, ScanStreamMessage::Result(result_event))
                            .await;
                    }
                }

                if processed - last_persisted >= 10
                    || TaskControl::signal(&task_signal) != TaskSignal::Run
                {
                    if let Err(err) =
                        sqlx::query("UPDATE scans SET processed = ?, found = ? WHERE id = ?")
                            .bind(processed)
                            .bind(found)
                            .bind(scan_id)
                            .execute(db)
                            .await
                    {
                        error!(
                            target: "domain_scanner::queue",
                            context = "storage",
                            scan_id = %scan_id,
                            processed,
                            found,
                            error = %err,
                            "failed to persist counters"
                        );
                        let _ = add_event_log(
                            db,
                            &streams,
                            scan_id,
                            "ERROR",
                            "storage.counters_persist_failed",
                            None,
                            Some("Failed to persist counters".to_string()),
                            vec![
                                ("processed", json!(processed)),
                                ("found", json!(found)),
                                ("error", json!(err.to_string())),
                            ],
                        )
                        .await;
                    }
                    last_persisted = processed;
                }

                publish_scan_status(
                    &streams,
                    scan_id,
                    "running",
                    total,
                    processed,
                    found,
                    deferred_retries.len() as i64,
                )
                .await;

                if feeder_done.load(Ordering::Relaxed)
                    && pending_domains.load(Ordering::Relaxed) == 0
                    && deferred_retries.is_empty()
                {
                    jobs_tx.take();
                }
            }
        }
    }

    if !deferred_retries.is_empty() {
        for (_, res) in deferred_retries.drain() {
            processed += 1;
            let _ = add_event_log(
                db,
                &streams,
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

            match sqlx::query_as::<_, ScanResultEvent>(
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
                    streams
                        .publish_scan(scan_id, ScanStreamMessage::Result(row))
                        .await;
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
        publish_scan_status(&streams, scan_id, "running", total, processed, found, 0).await;
    }

    match TaskControl::signal(&task_signal) {
        TaskSignal::Cancel => {
            let _ = add_event_log(
                db,
                &streams,
                scan_id,
                "WARN",
                "task.cancelled",
                None,
                Some("Scan cancelled".to_string()),
                vec![("processed", json!(processed)), ("found", json!(found))],
            )
            .await;
            // Soft-delete: mark as 'cancelled' to preserve results and logs.
            // Use DELETE /api/scan/:id on a finished/cancelled scan to hard-delete.
            if let Err(err) = sqlx::query(
                "UPDATE scans SET status = 'cancelled', processed = ?, found = ?, finished_at = CURRENT_TIMESTAMP WHERE id = ?",
            )
            .bind(processed)
            .bind(found)
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
            publish_scan_status(&streams, scan_id, "cancelled", total, processed, found, 0).await;
            streams.notify_scans();
            streams
                .publish_scan(scan_id, ScanStreamMessage::Complete(scan_id.to_string()))
                .await;
            streams.cleanup_scan(scan_id).await;
        }
        TaskSignal::Pause => {}
        TaskSignal::Run => {
            let _ = add_event_log(
                db,
                &streams,
                scan_id,
                "INFO",
                "task.summary",
                None,
                Some("Scan completed".to_string()),
                vec![("processed", json!(processed)), ("available", json!(found))],
            )
            .await;
            if let Err(err) = sqlx::query(
                "UPDATE scans
                 SET status = 'finished', processed = ?, found = ?, retry_not_before = NULL, finished_at = CURRENT_TIMESTAMP
                 WHERE id = ?",
            )
            .bind(processed)
            .bind(found)
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
            publish_scan_status(&streams, scan_id, "finished", total, processed, found, 0).await;
            streams.notify_scans();

            if found > 0 {
                let publish_title = if let Some(r) = &params.regex {
                    format!("Auto: {}", r)
                } else if params.domains.is_some() {
                    "Auto: Custom List".to_string()
                } else if !params.pattern.is_empty() {
                    format!("Auto: {}-letter {} ({})", params.length, params.suffix, params.pattern)
                } else {
                    format!("Auto: {}-letter {}", params.length, params.suffix)
                };

                let publish_req = crate::web::models::PublishScanRequest {
                    title: publish_title,
                    description: Some("Automatically published upon scan completion.".to_string()),
                };

                match crate::publish::create_published_scan(db, scan_id, &publish_req).await {
                    Ok(summary) => {
                        info!(target: "domain_scanner::queue", scan_id = %scan_id, "auto published successfully");
                        let _ = add_event_log(db, &streams, scan_id, "INFO", "task.published", None, Some(format!("Scan automatically published as {}", summary.slug)), vec![]).await;
                    }
                    Err(e) => {
                        error!(target: "domain_scanner::queue", scan_id = %scan_id, error = %e, "failed to auto publish");
                        let _ = add_event_log(db, &streams, scan_id, "ERROR", "task.publish_failed", None, Some("Failed to auto publish scan".to_string()), vec![("error", json!(e.to_string()))]).await;
                    }
                }
            }

            streams
                .publish_scan(scan_id, ScanStreamMessage::Complete(scan_id.to_string()))
                .await;
            streams.cleanup_scan(scan_id).await;
        }
    }

    task_control.unregister(scan_id);
}

async fn mark_scan_running(db: &SqlitePool, streams: &StreamHub, scan_id: &str) {
    if let Err(err) = sqlx::query(
        "UPDATE scans
         SET status = 'running', retry_not_before = NULL, started_at = CURRENT_TIMESTAMP
         WHERE id = ?",
    )
    .bind(scan_id)
    .execute(db)
    .await
    {
        error!(
            target: "domain_scanner::queue",
            context = "task_status",
            scan_id = %scan_id,
            status = "running",
            error = %err,
            "failed to mark task as running"
        );
        let _ = add_event_log(
            db,
            streams,
            scan_id,
            "ERROR",
            "task.status_update_failed",
            None,
            Some("Failed to mark task as running".to_string()),
            vec![
                ("error", json!(err.to_string())),
                ("status", json!("running")),
            ],
        )
        .await;
    }
}

async fn prepare_job_feeder(
    db: &SqlitePool,
    streams: &StreamHub,
    scan_id: &str,
    params: &StartScanRequest,
    resume_processed: i64,
    jobs_tx: &mpsc::Sender<String>,
    feeder_done: Arc<AtomicBool>,
    pending_domains: Arc<AtomicUsize>,
    task_signal: Arc<AtomicU8>,
    task_control: TaskControl,
) -> Result<i64, ()> {
    if let Some(domains) = params.domains.clone() {
        let total = domains.len() as i64;
        spawn_domain_feeder(
            domains
                .into_iter()
                .skip(resume_processed as usize)
                .collect(),
            jobs_tx.clone(),
            scan_id.to_string(),
            "manual",
            feeder_done,
            pending_domains,
            task_signal,
        );
        return Ok(total);
    }

    let domain_gen = match generator::generate_domains(
        params.length,
        params.suffix.clone(),
        params.pattern.clone(),
        params.regex.clone().unwrap_or_default(),
        "".to_string(),
        params.priority_words.clone().unwrap_or_default(),
        resume_processed,
    ) {
        Ok(generator) => generator,
        Err(err) => {
            let _ = add_event_log(
                db,
                streams,
                scan_id,
                "ERROR",
                "generator.failed",
                None,
                Some("Failed to generate domains".to_string()),
                vec![("error", json!(err.to_string()))],
            )
            .await;
            let _ = sqlx::query(
                "UPDATE scans SET status = 'failed', finished_at = CURRENT_TIMESTAMP WHERE id = ?",
            )
            .bind(scan_id)
            .execute(db)
            .await;
            task_control.unregister(scan_id);
            return Err(());
        }
    };

    let _ = add_event_log(
        db,
        streams,
        scan_id,
        "INFO",
        "generator.started",
        None,
        Some("Domain generator started".to_string()),
        vec![("total", json!(domain_gen.total_count))],
    )
    .await;

    let total = domain_gen.total_count as i64;
    spawn_generator_feeder(
        domain_gen,
        jobs_tx.clone(),
        scan_id.to_string(),
        feeder_done,
        pending_domains,
        task_signal,
    );
    Ok(total)
}

fn spawn_domain_feeder(
    domains: Vec<String>,
    jobs_tx: mpsc::Sender<String>,
    scan_id: String,
    source: &'static str,
    feeder_done: Arc<AtomicBool>,
    pending_domains: Arc<AtomicUsize>,
    task_signal: Arc<AtomicU8>,
) {
    tokio::spawn(async move {
        for domain in domains {
            if TaskControl::signal(&task_signal) != TaskSignal::Run {
                debug!(
                    target: "domain_scanner::queue",
                    context = "feeder",
                    scan_id = %scan_id,
                    source,
                    "feeder interrupted"
                );
                break;
            }
            pending_domains.fetch_add(1, Ordering::Relaxed);
            if jobs_tx.send(domain).await.is_err() {
                debug!(
                    target: "domain_scanner::queue",
                    context = "feeder",
                    scan_id = %scan_id,
                    source,
                    "feeder stopped because job queue closed"
                );
                pending_domains.fetch_sub(1, Ordering::Relaxed);
                break;
            }
        }
        feeder_done.store(true, Ordering::Relaxed);
    });
}

fn spawn_generator_feeder(
    domain_gen: generator::DomainGenerator,
    jobs_tx: mpsc::Sender<String>,
    scan_id: String,
    feeder_done: Arc<AtomicBool>,
    pending_domains: Arc<AtomicUsize>,
    task_signal: Arc<AtomicU8>,
) {
    tokio::spawn(async move {
        let mut generated = domain_gen.domains;
        while let Some(domain) = generated.recv().await {
            if TaskControl::signal(&task_signal) != TaskSignal::Run {
                debug!(
                    target: "domain_scanner::queue",
                    context = "feeder",
                    scan_id = %scan_id,
                    source = "generator",
                    "generator feeder interrupted"
                );
                break;
            }
            pending_domains.fetch_add(1, Ordering::Relaxed);
            if jobs_tx.send(domain).await.is_err() {
                debug!(
                    target: "domain_scanner::queue",
                    context = "feeder",
                    scan_id = %scan_id,
                    source = "generator",
                    "generator feeder stopped because job queue closed"
                );
                pending_domains.fetch_sub(1, Ordering::Relaxed);
                break;
            }
        }
        feeder_done.store(true, Ordering::Relaxed);
    });
}

async fn initialize_scan_counters(
    db: &SqlitePool,
    _streams: &StreamHub,
    scan_id: &str,
    total: i64,
    processed: i64,
    found: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE scans SET total = ?, processed = ?, found = ?, retry_not_before = NULL WHERE id = ?")
        .bind(total)
        .bind(processed)
        .bind(found)
        .bind(scan_id)
        .execute(db)
        .await
        .map(|_| ())
        .map(|_| ())
}

async fn add_log(
    db: &SqlitePool,
    streams: &StreamHub,
    scan_id: &str,
    level: &str,
    message: &str,
) -> Result<(), sqlx::Error> {
    let inserted = sqlx::query_as::<_, ScanLogEvent>(
        "INSERT INTO scan_logs (scan_id, level, message)
         VALUES (?, ?, ?)
         RETURNING id, message, level, created_at",
    )
    .bind(scan_id)
    .bind(level)
    .bind(message)
    .fetch_one(db)
    .await
    .map_err(|err| {
        warn!(
            target: "domain_scanner::queue",
            context = "scan_log",
            scan_id = %scan_id,
            level,
            error = %err,
            "failed to write scan log"
        );
        err
    })?;
    streams
        .publish_scan(scan_id, ScanStreamMessage::Log(inserted))
        .await;
    Ok(())
}

async fn add_event_log(
    db: &SqlitePool,
    streams: &StreamHub,
    scan_id: &str,
    level: &str,
    event: &str,
    domain: Option<&str>,
    message: Option<String>,
    fields: Vec<(&str, Value)>,
) -> Result<(), sqlx::Error> {
    let mut field_map = Map::new();
    for (key, value) in fields {
        field_map.insert(key.to_string(), value);
    }

    let payload = ScanLogRecord {
        event: event.to_string(),
        domain: domain.map(ToOwned::to_owned),
        message,
        fields: field_map,
    };

    let serialized = serde_json::to_string(&payload).unwrap_or_else(|err| {
        format!(
            r#"{{"event":"log.serialization_failed","message":"{}","fields":{{"source_event":"{}"}}}}"#,
            err, event
        )
    });

    add_log(db, streams, scan_id, level, &serialized).await
}

async fn publish_scan_status(
    streams: &StreamHub,
    scan_id: &str,
    status: &str,
    total: i64,
    processed: i64,
    found: i64,
    deferred: i64,
) {
    // NOTE: notify_scans() is intentionally NOT called here.
    // It should only be invoked on real state transitions (running, cancelled, finished)
    // by the caller, not on every per-domain progress update.
    streams
        .publish_scan(
            scan_id,
            ScanStreamMessage::Status(ScanStatus {
                id: scan_id.to_string(),
                status: status.to_string(),
                total,
                processed,
                found,
                deferred,
            }),
        )
        .await;
}

async fn get_result_counts(db: &SqlitePool, scan_id: &str) -> Result<(i64, i64), sqlx::Error> {
    let row = sqlx::query(
        "SELECT COUNT(*) AS processed, COALESCE(SUM(CASE WHEN available = 1 THEN 1 ELSE 0 END), 0) AS found
         FROM results WHERE scan_id = ?",
    )
    .bind(scan_id)
    .fetch_one(db)
    .await?;

    Ok((
        row.try_get("processed").unwrap_or(0),
        row.try_get("found").unwrap_or(0),
    ))
}

async fn get_next_retry_not_before(db: &SqlitePool) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar::<_, i64>(
        "SELECT MIN(retry_not_before) FROM scans
         WHERE status = 'pending'
           AND retry_not_before IS NOT NULL
           AND retry_not_before > ?",
    )
    .bind(now_epoch_seconds())
    .fetch_optional(db)
    .await
}

fn now_epoch_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn is_whois_rate_limited(res: &crate::DomainResult) -> bool {
    res.trace.iter().any(|step| step.starts_with("WHOIS: "))
        || res
            .error
            .as_deref()
            .map(|err| err.to_ascii_uppercase().contains("WHOIS"))
            .unwrap_or(false)
}
