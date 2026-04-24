use super::models::{StartScanRequest, StreamHub, TaskControl};
use super::scan_runtime::{add_event_log, mark_scan_running, run_scan_logic};
use crate::checker::CheckerRegistry;
use serde_json::json;
use sqlx::{Row, sqlite::SqlitePool};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{debug, error, info};

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
