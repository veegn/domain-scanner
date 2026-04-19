use super::models::{StartScanRequest, TaskControl, TaskSignal};
use crate::checker::CheckerRegistry;
use crate::generator;
use crate::worker;
use serde::Serialize;
use serde_json::{Map, Value, json};
use sqlx::{Row, sqlite::SqlitePool};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, error, info, warn};

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

/// The single task background worker.
pub async fn start_task_worker(
    db: SqlitePool,
    mut rx: mpsc::Receiver<()>,
    task_control: TaskControl,
    registry: Arc<CheckerRegistry>,
) {
    info!(
        target: "domain_scanner::queue",
        context = "worker",
        "background task worker started"
    );

    loop {
        let next_task = fetch_next_ready_task(&db).await;

        if let Some(row) = next_task {
            let scan_id: String = row.try_get("id").unwrap_or_default();

            let length: i64 = row.try_get("length").unwrap_or(0);
            let suffix: String = row.try_get("suffix").unwrap_or_default();
            let pattern: String = row.try_get("pattern").unwrap_or_default();
            let regex: Option<String> = row.try_get("regex").unwrap_or(None);

            let priority_words_json: String = row
                .try_get("priority_words")
                .unwrap_or_else(|_| "null".to_string());
            let domains_json: String = row
                .try_get("domains")
                .unwrap_or_else(|_| "null".to_string());

            let priority_words: Option<Vec<String>> =
                serde_json::from_str(&priority_words_json).unwrap_or(None);
            let domains: Option<Vec<String>> = serde_json::from_str(&domains_json).unwrap_or(None);

            let processed: i64 = row.try_get("processed").unwrap_or(0);
            let found: i64 = row.try_get("found").unwrap_or(0);

            let params = StartScanRequest {
                length: length as usize,
                suffix,
                pattern,
                regex,
                priority_words,
                domains,
            };

            info!(
                target: "domain_scanner::queue",
                context = "task_start",
                scan_id = %scan_id,
                "starting task"
            );
            let _ = add_event_log(
                &db,
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

            if let Err(err) = sqlx::query(
                "UPDATE scans
                 SET status = 'running', retry_not_before = NULL, started_at = CURRENT_TIMESTAMP
                 WHERE id = ?",
            )
            .bind(&scan_id)
            .execute(&db)
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
                    &db,
                    &scan_id,
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

            run_scan_logic(
                &db,
                &scan_id,
                params,
                processed,
                found,
                registry.clone(),
                task_control.clone(),
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
) {
    let task_signal = task_control.register(scan_id);
    let counts = get_result_counts(db, scan_id).await.unwrap_or((0, 0));
    let resume_processed = counts.0;
    let resume_found = counts.1;
    let _ = add_event_log(
        db,
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

    let total = if let Some(domains) = params.domains.clone() {
        let filtered_domains: Vec<String> = domains
            .into_iter()
            .skip(resume_processed as usize)
            .collect();
        let total = params.domains.as_ref().map(|d| d.len()).unwrap_or_default() as i64;
        let tx = jobs_tx.clone();
        let scan_id = scan_id.to_string();
        let signal_clone = task_signal.clone();
        let feeder_done_clone = feeder_done.clone();
        let pending_domains_clone = pending_domains.clone();
        tokio::spawn(async move {
            for domain in filtered_domains {
                if TaskControl::signal(&signal_clone) != TaskSignal::Run {
                    debug!(
                        target: "domain_scanner::queue",
                        context = "feeder",
                        scan_id = %scan_id,
                        source = "manual",
                        "feeder interrupted"
                    );
                    break;
                }
                pending_domains_clone.fetch_add(1, Ordering::Relaxed);
                if tx.send(domain).await.is_err() {
                    debug!(
                        target: "domain_scanner::queue",
                        context = "feeder",
                        scan_id = %scan_id,
                        source = "manual",
                        "feeder stopped because job queue closed"
                    );
                    pending_domains_clone.fetch_sub(1, Ordering::Relaxed);
                    break;
                }
            }
            feeder_done_clone.store(true, Ordering::Relaxed);
        });
        total
    } else {
        let domain_gen = match generator::generate_domains(
            params.length,
            params.suffix.clone(),
            params.pattern.clone(),
            params.regex.clone().unwrap_or_default(),
            "".to_string(),
            params.priority_words.clone().unwrap_or_default(),
            resume_processed,
        ) {
            Ok(generator) => {
                let _ = add_event_log(
                    db,
                    scan_id,
                    "INFO",
                    "generator.started",
                    None,
                    Some("Domain generator started".to_string()),
                    vec![("total", json!(generator.total_count))],
                )
                .await;
                generator
            }
            Err(e) => {
                let _ = add_event_log(
                    db,
                    scan_id,
                    "ERROR",
                    "generator.failed",
                    None,
                    Some("Failed to generate domains".to_string()),
                    vec![("error", json!(e.to_string()))],
                )
                .await;
                let _ = sqlx::query(
                    "UPDATE scans SET status = 'failed', finished_at = CURRENT_TIMESTAMP WHERE id = ?",
                )
                .bind(scan_id)
                .execute(db)
                .await;
                task_control.unregister(scan_id);
                return;
            }
        };
        let total = domain_gen.total_count as i64;
        let tx = jobs_tx.clone();
        let scan_id = scan_id.to_string();
        let signal_clone = task_signal.clone();
        let feeder_done_clone = feeder_done.clone();
        let pending_domains_clone = pending_domains.clone();
        tokio::spawn(async move {
            let mut generated = domain_gen.domains;
            while let Some(domain) = generated.recv().await {
                if TaskControl::signal(&signal_clone) != TaskSignal::Run {
                    debug!(
                        target: "domain_scanner::queue",
                        context = "feeder",
                        scan_id = %scan_id,
                        source = "generator",
                        "generator feeder interrupted"
                    );
                    break;
                }
                pending_domains_clone.fetch_add(1, Ordering::Relaxed);
                if tx.send(domain).await.is_err() {
                    debug!(
                        target: "domain_scanner::queue",
                        context = "feeder",
                        scan_id = %scan_id,
                        source = "generator",
                        "generator feeder stopped because job queue closed"
                    );
                    pending_domains_clone.fetch_sub(1, Ordering::Relaxed);
                    break;
                }
            }
            feeder_done_clone.store(true, Ordering::Relaxed);
        });
        total
    };
    let mut jobs_tx = Some(jobs_tx);
    let jobs_rx = Arc::new(Mutex::new(jobs_rx));

    let _ = add_event_log(
        db,
        scan_id,
        "INFO",
        "worker.pool",
        None,
        Some("Spawning worker threads".to_string()),
        vec![
            ("size", json!(10)),
            ("delay_ms", json!(500)),
            ("total", json!(total)),
        ],
    )
    .await;

    if let Err(e) = sqlx::query(
        "UPDATE scans SET total = ?, processed = ?, found = ?, retry_not_before = NULL WHERE id = ?",
    )
    .bind(total)
    .bind(resume_processed)
    .bind(resume_found)
    .bind(scan_id)
    .execute(db)
    .await
    {
        let _ = add_event_log(
            db,
            scan_id,
            "ERROR",
            "storage.counters_init_failed",
            None,
            Some("Failed to initialize scan counters".to_string()),
            vec![("error", json!(e.to_string()))],
        )
        .await;
        task_control.unregister(scan_id);
        return;
    }

    let (tx_results, mut rx_results) = mpsc::channel(100);
    let worker_throttle = Arc::new(worker::WorkerThrottle::new(Duration::from_millis(500)));

    for id in 1..=10 {
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
    let mut retry_attempts: HashMap<String, u32> = HashMap::new();

    loop {
        if feeder_done.load(Ordering::Relaxed) && pending_domains.load(Ordering::Relaxed) == 0 {
            jobs_tx.take();
        }

        let msg = match tokio::time::timeout(Duration::from_millis(100), rx_results.recv()).await {
            Ok(Some(msg)) => msg,
            Ok(None) => break,
            Err(_) => {
                if feeder_done.load(Ordering::Relaxed)
                    && pending_domains.load(Ordering::Relaxed) == 0
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
                        scan_id,
                        "INFO",
                        "domain.trace",
                        Some(res.domain.as_str()),
                        None,
                        vec![("steps", json!(res.trace))],
                    )
                    .await;
                }

                if res.retryable {
                    let attempt = retry_attempts.entry(res.domain.clone()).or_insert(0);
                    *attempt += 1;
                    let max_attempts = if res.rate_limited { 6 } else { 12 };
                    let should_retry = *attempt <= max_attempts;
                    if should_retry {
                        if res.rate_limited && is_whois_rate_limited(&res) {
                            let new_delay = worker_throttle.slow_down_by_percent(20);
                            let paused_until = worker_throttle.pause_for(Duration::from_secs(60));
                            let _ = add_event_log(
                                db,
                                scan_id,
                                "WARN",
                                "task.throttle_adjusted",
                                Some(res.domain.as_str()),
                                Some(
                                    "WHOIS rate limit detected; pausing task and reducing scan speed"
                                        .to_string(),
                                ),
                                vec![
                                    ("pause_secs", json!(60)),
                                    ("delay_ms", json!(new_delay.as_millis() as u64)),
                                    ("paused_until_epoch_ms", json!(paused_until)),
                                ],
                            )
                            .await;
                        }

                        let delay_secs =
                            compute_domain_retry_delay_secs(res.retry_after_secs, *attempt);
                        let reason = res
                            .error
                            .clone()
                            .unwrap_or_else(|| "transient failure".to_string());
                        let policy = if res.rate_limited {
                            "dynamic-rate-limit"
                        } else {
                            "continuous-timeout-retry"
                        };
                        let level = if res.rate_limited { "WARN" } else { "INFO" };
                        let _ = add_event_log(
                            db,
                            scan_id,
                            level,
                            "domain.retry",
                            Some(res.domain.as_str()),
                            Some(reason),
                            vec![
                                ("attempt", json!(*attempt)),
                                ("delay_secs", json!(delay_secs)),
                                ("policy", json!(policy)),
                                ("rate_limited", json!(res.rate_limited)),
                            ],
                        )
                        .await;

                        if let Some(sender) = jobs_tx.as_ref() {
                            let sender = sender.clone();
                            let signal_clone = task_signal.clone();
                            let domain = res.domain.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_secs(delay_secs)).await;
                                if TaskControl::signal(&signal_clone) != TaskSignal::Run {
                                    return;
                                }
                                let _ = sender.send(domain).await;
                            });
                            continue;
                        }
                    } else {
                        let _ = add_event_log(
                            db,
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
                            vec![("attempt", json!(*attempt))],
                        )
                        .await;
                    }
                }

                pending_domains.fetch_sub(1, Ordering::Relaxed);
                processed += 1;
                retry_attempts.remove(&res.domain);

                if res.available {
                    found += 1;
                    let _ = add_event_log(
                        db,
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
                        scan_id,
                        "INFO",
                        "domain.registered",
                        Some(res.domain.as_str()),
                        None,
                        fields,
                    )
                    .await;
                }

                if let Err(err) = sqlx::query(
                    "INSERT OR REPLACE INTO results (scan_id, domain, available, expiration_date, signatures)
                     VALUES (?, ?, ?, ?, ?)",
                )
                .bind(scan_id)
                .bind(&res.domain)
                .bind(res.available)
                .bind(res.expiration_date)
                .bind(res.signatures.join(","))
                .execute(db)
                .await
                {
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
                        scan_id,
                        "ERROR",
                        "storage.result_persist_failed",
                        Some(res.domain.as_str()),
                        Some("Failed to persist result".to_string()),
                        vec![("error", json!(err.to_string()))],
                    )
                    .await;
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

                if feeder_done.load(Ordering::Relaxed)
                    && pending_domains.load(Ordering::Relaxed) == 0
                {
                    jobs_tx.take();
                }
            }
        }
    }

    match TaskControl::signal(&task_signal) {
        TaskSignal::Cancel => {
            let _ = add_event_log(
                db,
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
        }
        TaskSignal::Pause => {}
        TaskSignal::Run => {
            let _ = add_event_log(
                db,
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
                    scan_id,
                    "ERROR",
                    "task.status_update_failed",
                    None,
                    Some("Failed to mark task finished".to_string()),
                    vec![("error", json!(err.to_string())), ("status", json!("finished"))],
                )
                .await;
            }
        }
    }

    task_control.unregister(scan_id);
}

async fn add_log(
    db: &SqlitePool,
    scan_id: &str,
    level: &str,
    message: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO scan_logs (scan_id, level, message) VALUES (?, ?, ?)")
        .bind(scan_id)
        .bind(level)
        .bind(message)
        .execute(db)
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
    Ok(())
}

async fn add_event_log(
    db: &SqlitePool,
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

    add_log(db, scan_id, level, &serialized).await
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

fn compute_domain_retry_delay_secs(server_suggested_secs: Option<u64>, attempt: u32) -> u64 {
    let exponential = 15u64.saturating_mul(2u64.saturating_pow(attempt.saturating_sub(1)));
    server_suggested_secs
        .unwrap_or(exponential)
        .max(exponential)
        .min(15 * 60)
}

fn is_whois_rate_limited(res: &crate::DomainResult) -> bool {
    res.trace.iter().any(|step| step.starts_with("WHOIS: "))
        || res
            .error
            .as_deref()
            .map(|err| err.to_ascii_uppercase().contains("WHOIS"))
            .unwrap_or(false)
}
