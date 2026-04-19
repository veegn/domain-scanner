use super::models::{StartScanRequest, TaskControl, TaskSignal};
use crate::checker::CheckerRegistry;
use crate::generator;
use crate::worker;
use sqlx::{Row, sqlite::SqlitePool};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, mpsc};

/// The single task background worker.
pub async fn start_task_worker(
    db: SqlitePool,
    mut rx: mpsc::Receiver<()>,
    task_control: TaskControl,
    registry: Arc<CheckerRegistry>,
) {
    println!("Background Task Worker started. Waiting for tasks...");

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

            println!("Starting Task: {}", scan_id);
            let _ = add_log(&db, &scan_id, "INFO", "Task picked up by background worker").await;
            let _ = add_log(
                &db,
                &scan_id,
                "INFO",
                &format!(
                    "TASK_CONFIG length={} suffix={} pattern={} regex={} source={}",
                    params.length,
                    params.suffix,
                    params.pattern,
                    params.regex.as_deref().unwrap_or("-"),
                    if params.domains.is_some() {
                        "manual-list"
                    } else {
                        "generated"
                    }
                ),
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
                eprintln!("Task {} failed to mark as running: {}", scan_id, err);
                let _ = add_log(
                    &db,
                    &scan_id,
                    "ERROR",
                    &format!("Failed to mark task as running: {}", err),
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

            println!("Finished Task: {}", scan_id);
            continue;
        }

        let next_retry_at = get_next_retry_not_before(&db).await.unwrap_or(None);
        if let Some(retry_at) = next_retry_at {
            let wait_secs = retry_at.saturating_sub(now_epoch_seconds()).max(1) as u64;
            println!(
                "No ready tasks. Background worker sleeping {}s until next retry window.",
                wait_secs
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
            eprintln!("Background worker failed to query next task: {}", e);
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
    let _ = add_log(
        db,
        scan_id,
        "INFO",
        &format!(
            "RESUME_STATE processed={} found={}",
            resume_processed, resume_found
        ),
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
                    eprintln!(
                        "Task {} feeder interrupted while enqueuing manual domains",
                        scan_id
                    );
                    break;
                }
                pending_domains_clone.fetch_add(1, Ordering::Relaxed);
                if tx.send(domain).await.is_err() {
                    eprintln!("Task {} feeder stopped because job queue closed", scan_id);
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
                let _ = add_log(
                    db,
                    scan_id,
                    "INFO",
                    &format!(
                        "Domain generator started. Total domains to check: {}",
                        generator.total_count
                    ),
                )
                .await;
                generator
            }
            Err(e) => {
                let err_msg = format!("Failed to generate domains: {}", e);
                let _ = add_log(db, scan_id, "ERROR", &err_msg).await;
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
                    eprintln!("Task {} generator feeder interrupted", scan_id);
                    break;
                }
                pending_domains_clone.fetch_add(1, Ordering::Relaxed);
                if tx.send(domain).await.is_err() {
                    eprintln!(
                        "Task {} generator feeder stopped because job queue closed",
                        scan_id
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

    let _ = add_log(db, scan_id, "INFO", "Spawning worker threads...").await;
    let _ = add_log(
        db,
        scan_id,
        "INFO",
        &format!("WORKER_POOL size=10 delay_ms=500 total={}", total),
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
        let _ = add_log(
            db,
            scan_id,
            "ERROR",
            &format!("Failed to initialize scan counters: {}", e),
        )
        .await;
        task_control.unregister(scan_id);
        return;
    }

    let (tx_results, mut rx_results) = mpsc::channel(100);

    for id in 1..=10 {
        let jobs = jobs_rx.clone();
        let tx = tx_results.clone();
        let delay = Duration::from_millis(500);
        let reg = registry.clone();
        let signal_clone = task_signal.clone();
        tokio::spawn(async move {
            worker::worker(id, jobs, tx, delay, reg, signal_clone).await;
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
            let _ = add_log(
                db,
                scan_id,
                "WARN",
                "Task signal changed from RUN; closing job queue",
            )
            .await;
        }

        match msg {
            crate::WorkerMessage::Scanning(domain) => {
                let _ = add_log(db, scan_id, "INFO", &format!("SCANNING {}", domain)).await;
            }
            crate::WorkerMessage::Result(res) => {
                if !res.trace.is_empty() {
                    let _ = add_log(
                        db,
                        scan_id,
                        "INFO",
                        &format!("TRACE {} :: {}", res.domain, res.trace.join(" | ")),
                    )
                    .await;
                }

                if res.retryable {
                    let attempt = retry_attempts.entry(res.domain.clone()).or_insert(0);
                    *attempt += 1;
                    let max_attempts = if res.rate_limited { 6 } else { 12 };
                    let should_retry = *attempt <= max_attempts;
                    if should_retry {
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
                        let _ = add_log(
                            db,
                            scan_id,
                            level,
                            &format!(
                                "RETRY {} :: attempt {} in {}s :: {} :: {}",
                                res.domain, *attempt, delay_secs, policy, reason
                            ),
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
                        let _ = add_log(
                            db,
                            scan_id,
                            "ERROR",
                            &format!(
                                "RETRY_EXHAUSTED {} :: after {} attempts :: {}",
                                res.domain,
                                *attempt,
                                res.error.as_deref().unwrap_or("transient failure")
                            ),
                        )
                        .await;
                    }
                }

                pending_domains.fetch_sub(1, Ordering::Relaxed);
                processed += 1;
                retry_attempts.remove(&res.domain);

                if res.available {
                    found += 1;
                    let _ =
                        add_log(db, scan_id, "INFO", &format!("AVAILABLE {}", res.domain)).await;
                } else if let Some(err) = res.error {
                    let _ = add_log(
                        db,
                        scan_id,
                        "WARN",
                        &format!("ERROR {} :: {}", res.domain, err),
                    )
                    .await;
                } else {
                    let mut message = format!("REGISTERED {}", res.domain);
                    if !res.signatures.is_empty() {
                        message.push_str(&format!(" :: {}", res.signatures.join(",")));
                    }
                    if let Some(expiration_date) = &res.expiration_date {
                        message.push_str(&format!(" :: expires {}", expiration_date));
                    }
                    let _ = add_log(db, scan_id, "INFO", &message).await;
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
                    eprintln!(
                        "Task {} failed to persist result for {}: {}",
                        scan_id, res.domain, err
                    );
                    let _ = add_log(
                        db,
                        scan_id,
                        "ERROR",
                        &format!("Failed to persist result for {}: {}", res.domain, err),
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
                        eprintln!(
                            "Task {} failed to persist counters processed={} found={}: {}",
                            scan_id, processed, found, err
                        );
                        let _ = add_log(
                            db,
                            scan_id,
                            "ERROR",
                            &format!(
                                "Failed to persist counters processed={} found={}: {}",
                                processed, found, err
                            ),
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
            let _ = add_log(
                db,
                scan_id,
                "WARN",
                &format!(
                    "Scan cancelled after {} domains processed. {} available found.",
                    processed, found
                ),
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
                eprintln!("Task {} failed to mark cancelled: {}", scan_id, err);
            }
        }
        TaskSignal::Pause => {}
        TaskSignal::Run => {
            let _ = add_log(
                db,
                scan_id,
                "INFO",
                &format!("SUMMARY processed={} available={}", processed, found),
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
                eprintln!("Task {} failed to mark finished: {}", scan_id, err);
                let _ = add_log(
                    db,
                    scan_id,
                    "ERROR",
                    &format!("Failed to mark task finished: {}", err),
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
            eprintln!(
                "Task {} failed to write scan log level={} message={}: {}",
                scan_id, level, message, err
            );
            err
        })?;
    Ok(())
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
