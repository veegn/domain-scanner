use super::models::{
    ScanLogEvent, ScanResultEvent, ScanStatus, ScanStreamMessage, StartScanRequest, StreamHub,
    TaskControl, TaskSignal,
};
use crate::generator;
use serde::Serialize;
use serde_json::{Map, Value, json};
use sqlx::{QueryBuilder, Row, Sqlite, sqlite::SqlitePool};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use tokio::sync::broadcast;
use tracing::{debug, error, warn};

pub(super) const MAX_EXCEPTION_REPLAY_ROUNDS: u32 = 3;
pub(super) const WORKER_COUNT: usize = 10;
pub(super) const WORKER_DELAY_MS: u64 = 500;
pub(super) const COUNTER_PERSIST_INTERVAL: i64 = 50;
pub(super) const STATUS_PUBLISH_INTERVAL: i64 = 10;
pub(super) const RESULT_FLUSH_BATCH_SIZE: usize = 50;
pub(super) const LOG_FLUSH_BATCH_SIZE: usize = 50;

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

pub(super) struct PendingResultPersist {
    pub(super) domain: String,
    pub(super) available: bool,
    pub(super) expiration_date: Option<String>,
    pub(super) signatures: String,
}

pub(super) struct PendingLogPersist {
    level: String,
    message: String,
}

pub(super) struct ScanRuntimeState {
    pub(super) processed: i64,
    pub(super) found: i64,
    pub(super) last_persisted: i64,
    pub(super) last_status_published: i64,
    pub(super) last_published_deferred: i64,
    pub(super) pending_result_flush: Vec<PendingResultPersist>,
    pub(super) pending_log_flush: Vec<PendingLogPersist>,
    pub(super) deferred_retries: HashMap<String, crate::DomainResult>,
    pub(super) replay_round: u32,
}

impl ScanRuntimeState {
    pub(super) fn new(processed: i64, found: i64) -> Self {
        Self {
            processed,
            found,
            last_persisted: processed,
            last_status_published: processed,
            last_published_deferred: 0,
            pending_result_flush: Vec::with_capacity(RESULT_FLUSH_BATCH_SIZE),
            pending_log_flush: Vec::with_capacity(LOG_FLUSH_BATCH_SIZE),
            deferred_retries: HashMap::new(),
            replay_round: 0,
        }
    }

    pub(super) fn deferred_count(&self) -> i64 {
        self.deferred_retries.len() as i64
    }
}

pub(super) async fn mark_scan_running(db: &SqlitePool, streams: &StreamHub, scan_id: &str) {
    if let Err(err) = sqlx::query(
        "UPDATE scans
         SET status = 'running',
             retry_not_before = NULL,
             started_at = COALESCE(started_at, CURRENT_TIMESTAMP)
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

pub(super) async fn add_event_log(
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

    let scan_stream = streams.sender_for_scan(scan_id).await;
    add_log(db, &scan_stream, scan_id, level, &serialized).await
}

pub(super) async fn prepare_job_feeder(
    db: &SqlitePool,
    streams: &StreamHub,
    scan_id: &str,
    params: &StartScanRequest,
    resume_processed: i64,
    jobs_tx: &async_channel::Sender<String>,
    feeder_done: Arc<AtomicBool>,
    pending_domains: Arc<AtomicUsize>,
    task_signal: Arc<AtomicU8>,
    task_control: TaskControl,
) -> Result<i64, ()> {
    if let Some(domains) = params.domains.clone() {
        let total = domains.len() as i64;
        spawn_domain_feeder(
            domains,
            resume_processed as usize,
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
    skip: usize,
    jobs_tx: async_channel::Sender<String>,
    scan_id: String,
    source: &'static str,
    feeder_done: Arc<AtomicBool>,
    pending_domains: Arc<AtomicUsize>,
    task_signal: Arc<AtomicU8>,
) {
    tokio::spawn(async move {
        for domain in domains.into_iter().skip(skip) {
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
    jobs_tx: async_channel::Sender<String>,
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

pub(super) async fn initialize_scan_counters(
    db: &SqlitePool,
    scan_id: &str,
    total: i64,
    processed: i64,
    found: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE scans SET total = ?, processed = ?, found = ?, retry_not_before = NULL WHERE id = ?",
    )
    .bind(total)
    .bind(processed)
    .bind(found)
    .bind(scan_id)
    .execute(db)
    .await
    .map(|_| ())
}

async fn add_log(
    db: &SqlitePool,
    scan_stream: &broadcast::Sender<ScanStreamMessage>,
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
    let _ = scan_stream.send(ScanStreamMessage::Log(inserted));
    Ok(())
}

async fn queue_log(
    pending: &mut Vec<PendingLogPersist>,
    db: &SqlitePool,
    scan_stream: &broadcast::Sender<ScanStreamMessage>,
    scan_id: &str,
    level: &str,
    message: &str,
) -> Result<(), sqlx::Error> {
    pending.push(PendingLogPersist {
        level: level.to_string(),
        message: message.to_string(),
    });

    if pending.len() >= LOG_FLUSH_BATCH_SIZE {
        flush_pending_logs(db, scan_stream, scan_id, pending).await;
    }

    Ok(())
}

pub(super) async fn queue_event_log(
    pending: &mut Vec<PendingLogPersist>,
    db: &SqlitePool,
    scan_stream: &broadcast::Sender<ScanStreamMessage>,
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

    queue_log(pending, db, scan_stream, scan_id, level, &serialized).await
}

pub(super) async fn publish_scan_status(
    scan_stream: &broadcast::Sender<ScanStreamMessage>,
    scan_id: &str,
    status: &str,
    total: i64,
    processed: i64,
    found: i64,
    deferred: i64,
) {
    let _ = scan_stream.send(ScanStreamMessage::Status(ScanStatus {
        id: scan_id.to_string(),
        status: status.to_string(),
        total,
        processed,
        found,
        deferred,
    }));
}

pub(super) async fn get_result_counts(
    db: &SqlitePool,
    scan_id: &str,
) -> Result<(i64, i64), sqlx::Error> {
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

pub(super) async fn flush_pending_state_logs(
    db: &SqlitePool,
    scan_stream: &broadcast::Sender<ScanStreamMessage>,
    scan_id: &str,
    state: &mut ScanRuntimeState,
) {
    if !state.pending_log_flush.is_empty() {
        flush_pending_logs(db, scan_stream, scan_id, &mut state.pending_log_flush).await;
    }
}

pub(super) async fn flush_scan_buffers(
    db: &SqlitePool,
    streams: &StreamHub,
    scan_stream: &broadcast::Sender<ScanStreamMessage>,
    scan_id: &str,
    state: &mut ScanRuntimeState,
) {
    if !state.pending_result_flush.is_empty() {
        flush_pending_results(
            db,
            streams,
            scan_stream,
            scan_id,
            &mut state.pending_result_flush,
        )
        .await;
    }
    flush_pending_state_logs(db, scan_stream, scan_id, state).await;
}

pub(super) async fn flush_pending_results(
    db: &SqlitePool,
    streams: &StreamHub,
    scan_stream: &broadcast::Sender<ScanStreamMessage>,
    scan_id: &str,
    pending: &mut Vec<PendingResultPersist>,
) {
    if pending.is_empty() {
        return;
    }

    let batch = std::mem::take(pending);
    let available_domains: Vec<String> = batch
        .iter()
        .filter(|row| row.available)
        .map(|row| row.domain.clone())
        .collect();

    let mut builder: QueryBuilder<'_, Sqlite> = QueryBuilder::new(
        "INSERT OR REPLACE INTO results (scan_id, domain, available, expiration_date, signatures) ",
    );
    builder.push_values(batch.iter(), |mut row, result| {
        row.push_bind(scan_id)
            .push_bind(&result.domain)
            .push_bind(result.available)
            .push_bind(&result.expiration_date)
            .push_bind(&result.signatures);
    });

    if let Err(err) = builder.build().execute(db).await {
        error!(
            target: "domain_scanner::queue",
            context = "storage",
            scan_id = %scan_id,
            error = %err,
            batch_size = batch.len(),
            "failed to persist result batch"
        );
        let _ = add_event_log(
            db,
            streams,
            scan_id,
            "ERROR",
            "storage.result_batch_persist_failed",
            None,
            Some("Failed to persist result batch".to_string()),
            vec![
                ("batch_size", json!(batch.len())),
                ("error", json!(err.to_string())),
            ],
        )
        .await;
        return;
    }

    if available_domains.is_empty() {
        return;
    }

    let mut query: QueryBuilder<'_, Sqlite> = QueryBuilder::new(
        "SELECT rowid as event_id, domain, available, expiration_date, signatures
         FROM results
         WHERE scan_id = ",
    );
    query.push_bind(scan_id);
    query.push(" AND domain IN (");
    {
        let mut separated = query.separated(", ");
        for domain in &available_domains {
            separated.push_bind(domain);
        }
    }
    query.push(")");

    match query.build_query_as::<ScanResultEvent>().fetch_all(db).await {
        Ok(rows) => {
            let row_by_domain: HashMap<String, ScanResultEvent> =
                rows.into_iter().map(|row| (row.domain.clone(), row)).collect();
            for domain in available_domains {
                if let Some(row) = row_by_domain.get(&domain) {
                    let _ = scan_stream.send(ScanStreamMessage::Result(row.clone()));
                }
            }
        }
        Err(err) => {
            error!(
                target: "domain_scanner::queue",
                context = "storage",
                scan_id = %scan_id,
                error = %err,
                "failed to load persisted available result batch"
            );
            let _ = add_event_log(
                db,
                streams,
                scan_id,
                "ERROR",
                "storage.result_batch_reload_failed",
                None,
                Some("Failed to load persisted available result batch".to_string()),
                vec![("error", json!(err.to_string()))],
            )
            .await;
        }
    }
}

async fn flush_pending_logs(
    db: &SqlitePool,
    scan_stream: &broadcast::Sender<ScanStreamMessage>,
    scan_id: &str,
    pending: &mut Vec<PendingLogPersist>,
) {
    if pending.is_empty() {
        return;
    }

    let batch = std::mem::take(pending);
    let mut builder: QueryBuilder<'_, Sqlite> =
        QueryBuilder::new("INSERT INTO scan_logs (scan_id, level, message) ");
    builder.push_values(batch.iter(), |mut row, log| {
        row.push_bind(scan_id)
            .push_bind(&log.level)
            .push_bind(&log.message);
    });

    if let Err(err) = builder.build().execute(db).await {
        warn!(
            target: "domain_scanner::queue",
            context = "scan_log",
            scan_id = %scan_id,
            error = %err,
            batch_size = batch.len(),
            "failed to write scan log batch"
        );
        return;
    }

    let count = batch.len() as i64;
    match sqlx::query_as::<_, ScanLogEvent>(
        "SELECT id, message, level, created_at
         FROM scan_logs
         WHERE scan_id = ?
         ORDER BY id DESC
         LIMIT ?",
    )
    .bind(scan_id)
    .bind(count)
    .fetch_all(db)
    .await
    {
        Ok(mut inserted) => {
            inserted.reverse();
            for log in inserted {
                let _ = scan_stream.send(ScanStreamMessage::Log(log));
            }
        }
        Err(err) => {
            warn!(
                target: "domain_scanner::queue",
                context = "scan_log",
                scan_id = %scan_id,
                error = %err,
                "failed to reload scan log batch for streaming"
            );
        }
    }
}

pub(super) fn is_whois_rate_limited(res: &crate::DomainResult) -> bool {
    res.trace.iter().any(|step| step.starts_with("WHOIS: "))
        || res
            .error
            .as_deref()
            .map(|err| err.to_ascii_uppercase().contains("WHOIS"))
            .unwrap_or(false)
}
