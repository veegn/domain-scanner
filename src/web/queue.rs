use super::models::{StartScanRequest, StreamHub, TaskControl};
use super::scan_runtime::{add_event_log, run_scan_logic};
use crate::checker::CheckerRegistry;
use crate::config::SchedulerConfig;
use serde_json::json;
use sqlx::{Row, sqlite::SqlitePool};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Semaphore;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};

struct PendingScanTask {
    scan_id: String,
    scheduler_key: String,
    params: StartScanRequest,
}

struct CompletedScanTask {
    scan_id: String,
    scheduler_key: String,
}

/// Background scheduler. Runs different TLD groups concurrently while keeping
/// scans for the same scheduler key serialized.
pub async fn start_task_worker(
    db: SqlitePool,
    mut rx: mpsc::Receiver<()>,
    task_control: TaskControl,
    registry: Arc<CheckerRegistry>,
    streams: StreamHub,
    scheduler_config: SchedulerConfig,
    global_check_permits: Arc<Semaphore>,
) {
    let max_parallel_tlds = scheduler_config.max_parallel_tlds.max(1);
    let workers_per_scan = scheduler_config.workers_per_scan.max(1);
    info!(
        target: "domain_scanner::queue",
        context = "worker",
        max_parallel_tlds,
        workers_per_scan,
        max_global_checks = scheduler_config.max_global_checks.max(1),
        "background task scheduler started"
    );

    let mut running = JoinSet::<CompletedScanTask>::new();
    let mut active_scheduler_keys = HashSet::<String>::new();

    loop {
        schedule_ready_tasks(
            &db,
            &streams,
            &task_control,
            &registry,
            &mut running,
            &mut active_scheduler_keys,
            max_parallel_tlds,
            workers_per_scan,
            global_check_permits.clone(),
        )
        .await;

        if running.is_empty() {
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
            continue;
        }

        tokio::select! {
            completed = running.join_next() => {
                match completed {
                    Some(Ok(task)) => {
                        active_scheduler_keys.remove(&task.scheduler_key);
                        info!(
                            target: "domain_scanner::queue",
                            context = "task_finish",
                            scan_id = %task.scan_id,
                            scheduler_key = %task.scheduler_key,
                            "task processing loop exited"
                        );
                    }
                    Some(Err(err)) => {
                        warn!(
                            target: "domain_scanner::queue",
                            context = "task_finish",
                            error = %err,
                            "task processing task exited unexpectedly"
                        );
                    }
                    None => {}
                }
            }
            signal = rx.recv() => {
                if signal.is_none() {
                    break;
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
}

async fn schedule_ready_tasks(
    db: &SqlitePool,
    streams: &StreamHub,
    task_control: &TaskControl,
    registry: &Arc<CheckerRegistry>,
    running: &mut JoinSet<CompletedScanTask>,
    active_scheduler_keys: &mut HashSet<String>,
    max_parallel_tlds: usize,
    workers_per_scan: usize,
    global_check_permits: Arc<Semaphore>,
) {
    while active_scheduler_keys.len() < max_parallel_tlds {
        let candidates = fetch_ready_task_candidates(db).await;
        let Some(task) = candidates
            .into_iter()
            .map(PendingScanTask::from_row)
            .find(|task| !active_scheduler_keys.contains(&task.scheduler_key))
        else {
            break;
        };

        if !claim_task(db, &task.scan_id, &task.scheduler_key).await {
            continue;
        }

        let scan_id = task.scan_id.clone();
        let scheduler_key = task.scheduler_key.clone();
        let params = task.params.clone();
        let params_for_log = params.clone();
        let db = db.clone();
        let streams = streams.clone();
        let task_control = task_control.clone();
        let registry = registry.clone();
        let permits = global_check_permits.clone();

        active_scheduler_keys.insert(scheduler_key.clone());
        running.spawn(async move {
            info!(
                target: "domain_scanner::queue",
                context = "task_start",
                scan_id = %scan_id,
                scheduler_key = %scheduler_key,
                "starting task"
            );
            emit_task_start_logs(&db, &streams, &scan_id, &scheduler_key, &params_for_log).await;

            run_scan_logic(
                &db,
                &scan_id,
                params,
                registry,
                task_control,
                &streams,
                workers_per_scan,
                permits,
            )
            .await;

            CompletedScanTask {
                scan_id,
                scheduler_key,
            }
        });
    }
}

async fn emit_task_start_logs(
    db: &SqlitePool,
    streams: &StreamHub,
    scan_id: &str,
    scheduler_key: &str,
    params: &StartScanRequest,
) {
    let _ = add_event_log(
        db,
        streams,
        scan_id,
        "INFO",
        "task.picked",
        None,
        Some("Task picked up by background scheduler".to_string()),
        vec![("scheduler_key", json!(scheduler_key))],
    )
    .await;
    let _ = add_event_log(
        db,
        streams,
        scan_id,
        "INFO",
        "task.config",
        None,
        None,
        vec![
            ("length", json!(params.length)),
            ("suffix", json!(params.suffix)),
            ("pattern", json!(params.pattern)),
            ("regex", json!(params.regex.as_deref().unwrap_or("-"))),
            ("scheduler_key", json!(scheduler_key)),
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
        let dictionary_words_json: String = row
            .try_get("dictionary_words")
            .unwrap_or_else(|_| "null".to_string());
        let dictionary_ids_json: String = row
            .try_get("dictionary_ids")
            .unwrap_or_else(|_| "null".to_string());

        Self {
            scan_id,
            params: {
                let params = StartScanRequest {
                    length: row.try_get::<i64, _>("length").unwrap_or(0) as usize,
                    suffix: row.try_get("suffix").unwrap_or_default(),
                    pattern: row.try_get("pattern").unwrap_or_default(),
                    regex: row.try_get("regex").unwrap_or(None),
                    priority_words: serde_json::from_str(&priority_words_json).unwrap_or(None),
                    domains: serde_json::from_str(&domains_json).unwrap_or(None),
                    dictionary_words: serde_json::from_str(&dictionary_words_json).unwrap_or(None),
                    dictionary_id: row.try_get("dictionary_id").unwrap_or(None),
                    dictionary_ids: serde_json::from_str(&dictionary_ids_json).unwrap_or(None),
                    separator: row.try_get("separator").unwrap_or(None),
                    format_template: row.try_get("format_template").unwrap_or(None),
                    prefix: row.try_get("prefix").unwrap_or(None),
                    postfix: row.try_get("postfix").unwrap_or(None),
                };
                params
            },
            scheduler_key: row
                .try_get::<Option<String>, _>("scheduler_key")
                .ok()
                .flatten()
                .filter(|key| !key.trim().is_empty())
                .unwrap_or_default(),
        }
        .with_scheduler_key()
    }

    fn with_scheduler_key(mut self) -> Self {
        if self.scheduler_key.is_empty() {
            self.scheduler_key = self.params.scheduler_key();
        }
        self
    }
}

async fn fetch_ready_task_candidates(db: &SqlitePool) -> Vec<sqlx::sqlite::SqliteRow> {
    match sqlx::query(
        "
        SELECT s.id, s.length, s.suffix, s.pattern, s.regex, s.processed, s.found, s.scheduler_key,
               p.priority_words, p.domains, p.dictionary_words, p.prefix, p.postfix, p.dictionary_id, p.dictionary_ids, p.separator, p.format_template
        FROM scans s
        LEFT JOIN scan_payloads p ON s.id = p.scan_id
        WHERE s.status = 'pending'
          AND (s.retry_not_before IS NULL OR s.retry_not_before <= ?)
        ORDER BY s.priority DESC, s.created_at ASC LIMIT 50
    ",
    )
    .bind(now_epoch_seconds())
    .fetch_all(db)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!(
                target: "domain_scanner::queue",
                context = "scheduler",
                error = %e,
                "failed to query next task"
            );
            Vec::new()
        }
    }
}

async fn claim_task(db: &SqlitePool, scan_id: &str, scheduler_key: &str) -> bool {
    match sqlx::query(
        "UPDATE scans
         SET status = 'running',
             retry_not_before = NULL,
             scheduler_key = COALESCE(NULLIF(scheduler_key, ''), ?),
             started_at = COALESCE(started_at, CURRENT_TIMESTAMP)
         WHERE id = ? AND status = 'pending'",
    )
    .bind(scheduler_key)
    .bind(scan_id)
    .execute(db)
    .await
    {
        Ok(result) => result.rows_affected() == 1,
        Err(err) => {
            error!(
                target: "domain_scanner::queue",
                context = "scheduler",
                scan_id = %scan_id,
                error = %err,
                "failed to claim task"
            );
            false
        }
    }
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
