use super::models::{
    ScanLogEvent, ScanResultEvent, ScanStatus, ScanStreamMessage, StartScanRequest, StreamHub,
    TaskControl, TaskSignal,
};
use crate::generator::{self, DictionaryCombinator};
use serde::Serialize;
use serde_json::{Map, Value, json};
use sqlx::{QueryBuilder, Row, Sqlite, sqlite::SqlitePool};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tracing::{debug, error, warn};

pub(super) const MAX_EXCEPTION_REPLAY_ROUNDS: u32 = 3;
pub(super) const WORKER_DELAY_MS: u64 = 1_000;
pub(super) const COUNTER_PERSIST_INTERVAL: i64 = 50;
pub(super) const STATUS_PUBLISH_INTERVAL: i64 = 10;
pub(super) const RESULT_FLUSH_BATCH_SIZE: usize = 50;
pub(super) const LOG_FLUSH_BATCH_SIZE: usize = 50;
const STORAGE_FLUSH_ATTEMPTS: usize = 4;
const STORAGE_FLUSH_BASE_DELAY_MS: u64 = 100;

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
    pub(super) registration_record_absent: bool,
    pub(super) purchasable: Option<bool>,
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
    pub(super) deferred_retry_ready_at: HashMap<String, Instant>,
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
            deferred_retry_ready_at: HashMap::new(),
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
    _resume_processed: i64,
    jobs_tx: &async_channel::Sender<String>,
    feeder_done: Arc<AtomicBool>,
    pending_domains: Arc<AtomicUsize>,
    task_signal: Arc<AtomicU8>,
    task_control: TaskControl,
) -> Result<i64, ()> {
    let scan_stream = streams.sender_for_scan(scan_id).await;
    let already_processed = match get_processed_domains(db, scan_id).await {
        Ok(domains) => Arc::new(domains),
        Err(err) => {
            let _ = add_event_log(
                db,
                streams,
                scan_id,
                "ERROR",
                "storage.resume_state_failed",
                None,
                Some("Failed to load processed domains for resume".to_string()),
                vec![("error", json!(err.to_string()))],
            )
            .await;
            let _ = sqlx::query(
                "UPDATE scans SET status = 'failed', finished_at = CURRENT_TIMESTAMP WHERE id = ?",
            )
            .bind(scan_id)
            .execute(db)
            .await;
            return Err(());
        }
    };

    if let Some(domains) = params.domains.clone() {
        let total = domains.len() as i64;
        spawn_domain_feeder(
            domains,
            already_processed.clone(),
            jobs_tx.clone(),
            scan_id.to_string(),
            "manual",
            feeder_done,
            pending_domains,
            task_signal,
            scan_stream.clone(),
        );
        return Ok(total);
    }

    if let Some(dict_ids) = &params.dictionary_ids
        && !dict_ids.is_empty()
    {
        let all_words = match crate::web::dictionary::load_multiple_dictionary_words(dict_ids).await
        {
            Ok(words) => words,
            Err(err) => {
                let _ = add_event_log(
                    db,
                    streams,
                    scan_id,
                    "ERROR",
                    "dictionary.load_failed",
                    None,
                    Some(format!("Failed to load dictionaries: {}", err)),
                    vec![
                        ("dictionary_ids", json!(dict_ids)),
                        ("error", json!(err.to_string())),
                    ],
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

        let suffix = params.suffix.clone();

        let total: usize = all_words.iter().map(|wl| wl.len()).product();
        let total_i64 = total as i64;

        let combinator = if let Some(template) = &params.format_template {
            DictionaryCombinator::new(all_words, template.clone(), suffix)
        } else {
            let separator = params.separator.clone().unwrap_or_default();
            let prefix = params.prefix.clone().unwrap_or_default();
            let postfix = params.postfix.clone().unwrap_or_default();
            DictionaryCombinator::from_parts(all_words, &prefix, &separator, &postfix, suffix)
        };

        spawn_combinator_feeder(
            combinator,
            already_processed.clone(),
            jobs_tx.clone(),
            scan_id.to_string(),
            feeder_done,
            pending_domains,
            task_signal,
            scan_stream.clone(),
        );
        return Ok(total_i64);
    }

    if let Some(dict_id) = &params.dictionary_id {
        let dict_words = match crate::web::dictionary::load_dictionary_words(dict_id).await {
            Ok(words) => words,
            Err(err) => {
                let _ = add_event_log(
                    db,
                    streams,
                    scan_id,
                    "ERROR",
                    "dictionary.load_failed",
                    None,
                    Some(format!("Failed to load dictionary {}: {}", dict_id, err)),
                    vec![
                        ("dictionary_id", json!(dict_id)),
                        ("error", json!(err.to_string())),
                    ],
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

        let total = dict_words.len() as i64;
        let prefix = params.prefix.clone().unwrap_or_default();
        let postfix = params.postfix.clone().unwrap_or_default();
        let suffix = params.suffix.clone();

        let domains: Vec<String> = dict_words
            .into_iter()
            .map(|word| {
                if word.contains('.') {
                    word
                } else {
                    format!("{}{}{}{}", prefix, word, postfix, suffix)
                }
            })
            .collect();

        spawn_domain_feeder(
            domains,
            already_processed.clone(),
            jobs_tx.clone(),
            scan_id.to_string(),
            "dictionary",
            feeder_done,
            pending_domains,
            task_signal,
            scan_stream.clone(),
        );
        return Ok(total);
    }

    if let Some(dict_words) = params.dictionary_words.clone() {
        let total = dict_words.len() as i64;
        let prefix = params.prefix.clone().unwrap_or_default();
        let postfix = params.postfix.clone().unwrap_or_default();
        let suffix = params.suffix.clone();

        let domains: Vec<String> = dict_words
            .into_iter()
            .map(|word| {
                if word.contains('.') {
                    word
                } else {
                    format!("{}{}{}{}", prefix, word, postfix, suffix)
                }
            })
            .collect();

        spawn_domain_feeder(
            domains,
            already_processed.clone(),
            jobs_tx.clone(),
            scan_id.to_string(),
            "dictionary",
            feeder_done,
            pending_domains,
            task_signal,
            scan_stream.clone(),
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
        0,
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
        already_processed,
        jobs_tx.clone(),
        scan_id.to_string(),
        feeder_done,
        pending_domains,
        task_signal,
        scan_stream.clone(),
    );
    Ok(total)
}

fn emit_queued_event(scan_stream: &broadcast::Sender<ScanStreamMessage>, domain: &str) {
    let _ = scan_stream.send(ScanStreamMessage::Log(ScanLogEvent {
        id: 0,
        message: json!({"event":"domain.queued","domain":domain}).to_string(),
        level: "INFO".to_string(),
        created_at: String::new(),
    }));
}

fn spawn_domain_feeder(
    domains: Vec<String>,
    already_processed: Arc<HashSet<String>>,
    jobs_tx: async_channel::Sender<String>,
    scan_id: String,
    source: &'static str,
    feeder_done: Arc<AtomicBool>,
    pending_domains: Arc<AtomicUsize>,
    task_signal: Arc<AtomicU8>,
    scan_stream: broadcast::Sender<ScanStreamMessage>,
) {
    tokio::spawn(async move {
        for domain in domains {
            if already_processed.contains(&domain) {
                continue;
            }
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
            if jobs_tx.send(domain.clone()).await.is_err() {
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
            emit_queued_event(&scan_stream, &domain);
        }
        feeder_done.store(true, Ordering::Relaxed);
    });
}

fn spawn_generator_feeder(
    domain_gen: generator::DomainGenerator,
    already_processed: Arc<HashSet<String>>,
    jobs_tx: async_channel::Sender<String>,
    scan_id: String,
    feeder_done: Arc<AtomicBool>,
    pending_domains: Arc<AtomicUsize>,
    task_signal: Arc<AtomicU8>,
    scan_stream: broadcast::Sender<ScanStreamMessage>,
) {
    tokio::spawn(async move {
        let mut generated = domain_gen.domains;
        while let Some(domain) = generated.recv().await {
            if already_processed.contains(&domain) {
                continue;
            }
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
            if jobs_tx.send(domain.clone()).await.is_err() {
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
            emit_queued_event(&scan_stream, &domain);
        }
        feeder_done.store(true, Ordering::Relaxed);
    });
}

fn spawn_combinator_feeder(
    mut combinator: DictionaryCombinator,
    already_processed: Arc<HashSet<String>>,
    jobs_tx: async_channel::Sender<String>,
    scan_id: String,
    feeder_done: Arc<AtomicBool>,
    pending_domains: Arc<AtomicUsize>,
    task_signal: Arc<AtomicU8>,
    scan_stream: broadcast::Sender<ScanStreamMessage>,
) {
    tokio::spawn(async move {
        for domain in combinator.by_ref() {
            if already_processed.contains(&domain) {
                continue;
            }
            if TaskControl::signal(&task_signal) != TaskSignal::Run {
                debug!(
                    target: "domain_scanner::queue",
                    context = "feeder",
                    scan_id = %scan_id,
                    source = "combinator",
                    "combinator feeder interrupted"
                );
                break;
            }
            pending_domains.fetch_add(1, Ordering::Relaxed);
            if jobs_tx.send(domain.clone()).await.is_err() {
                debug!(
                    target: "domain_scanner::queue",
                    context = "feeder",
                    scan_id = %scan_id,
                    source = "combinator",
                    "combinator feeder stopped because job queue closed"
                );
                pending_domains.fetch_sub(1, Ordering::Relaxed);
                break;
            }
            emit_queued_event(&scan_stream, &domain);
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
        flush_pending_logs(db, scan_stream, scan_id, pending).await?;
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
        "SELECT COUNT(*) AS processed,
                COALESCE(SUM(CASE WHEN registration_record_absent = 1 THEN 1 ELSE 0 END), 0) AS found
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

async fn get_processed_domains(
    db: &SqlitePool,
    scan_id: &str,
) -> Result<HashSet<String>, sqlx::Error> {
    let rows = sqlx::query_scalar::<_, String>("SELECT domain FROM results WHERE scan_id = ?")
        .bind(scan_id)
        .fetch_all(db)
        .await?;

    Ok(rows.into_iter().collect())
}

pub(super) async fn flush_pending_state_logs(
    db: &SqlitePool,
    scan_stream: &broadcast::Sender<ScanStreamMessage>,
    scan_id: &str,
    state: &mut ScanRuntimeState,
) {
    if !state.pending_log_flush.is_empty()
        && let Err(err) =
            flush_pending_logs(db, scan_stream, scan_id, &mut state.pending_log_flush).await
    {
        warn!(
            target: "domain_scanner::queue",
            context = "scan_log",
            scan_id = %scan_id,
            error = %err,
            pending = state.pending_log_flush.len(),
            "scan log batch remains buffered after retry exhaustion"
        );
    }
}

pub(super) async fn flush_scan_buffers(
    db: &SqlitePool,
    streams: &StreamHub,
    scan_stream: &broadcast::Sender<ScanStreamMessage>,
    scan_id: &str,
    state: &mut ScanRuntimeState,
) -> Result<(), sqlx::Error> {
    let result_flush = if state.pending_result_flush.is_empty() {
        Ok(())
    } else {
        flush_pending_results(db, scan_stream, scan_id, &mut state.pending_result_flush).await
    };
    flush_pending_state_logs(db, scan_stream, scan_id, state).await;
    streams.notify_scans();
    result_flush
}

pub(super) async fn flush_pending_results(
    db: &SqlitePool,
    scan_stream: &broadcast::Sender<ScanStreamMessage>,
    scan_id: &str,
    pending: &mut Vec<PendingResultPersist>,
) -> Result<(), sqlx::Error> {
    while !pending.is_empty() {
        let mut attempt = 1;
        loop {
            match persist_pending_result_batch(db, scan_stream, scan_id, pending).await {
                Ok(()) => break,
                Err(err) if attempt < STORAGE_FLUSH_ATTEMPTS => {
                    let delay_ms = STORAGE_FLUSH_BASE_DELAY_MS << (attempt - 1);
                    warn!(
                        target: "domain_scanner::queue",
                        context = "storage",
                        scan_id = %scan_id,
                        error = %err,
                        attempt,
                        pending = pending.len(),
                        retry_delay_ms = delay_ms,
                        "result batch write failed; retaining it for retry"
                    );
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    attempt += 1;
                }
                Err(err) => {
                    error!(
                        target: "domain_scanner::queue",
                        context = "storage",
                        scan_id = %scan_id,
                        error = %err,
                        attempts = attempt,
                        pending = pending.len(),
                        "result batch write retries exhausted; batch is still buffered"
                    );
                    return Err(err);
                }
            }
        }
    }

    Ok(())
}

async fn persist_pending_result_batch(
    db: &SqlitePool,
    scan_stream: &broadcast::Sender<ScanStreamMessage>,
    scan_id: &str,
    pending: &mut Vec<PendingResultPersist>,
) -> Result<(), sqlx::Error> {
    if pending.is_empty() {
        return Ok(());
    }

    let batch_len = pending.len().min(RESULT_FLUSH_BATCH_SIZE);

    let mut builder: QueryBuilder<'_, Sqlite> = QueryBuilder::new(
        "INSERT OR REPLACE INTO results
            (scan_id, domain, available, registration_record_absent, purchasable, expiration_date, signatures) ",
    );
    builder.push_values(pending[..batch_len].iter(), |mut row, result| {
        row.push_bind(scan_id)
            .push_bind(&result.domain)
            // Never claim purchase availability through the legacy field.
            .push_bind(false)
            .push_bind(result.registration_record_absent)
            .push_bind(result.purchasable)
            .push_bind(&result.expiration_date)
            .push_bind(&result.signatures);
    });
    builder.push(
        " RETURNING rowid as event_id, domain, registration_record_absent, purchasable,
          expiration_date, signatures",
    );

    let rows = builder
        .build_query_as::<ScanResultEvent>()
        .fetch_all(db)
        .await?;

    pending.drain(..batch_len);
    for row in rows {
        if row.registration_record_absent {
            let _ = scan_stream.send(ScanStreamMessage::Result(row));
        }
    }

    Ok(())
}

async fn flush_pending_logs(
    db: &SqlitePool,
    scan_stream: &broadcast::Sender<ScanStreamMessage>,
    scan_id: &str,
    pending: &mut Vec<PendingLogPersist>,
) -> Result<(), sqlx::Error> {
    while !pending.is_empty() {
        let mut attempt = 1;
        loop {
            match persist_pending_log_batch(db, scan_stream, scan_id, pending).await {
                Ok(()) => break,
                Err(err) if attempt < STORAGE_FLUSH_ATTEMPTS => {
                    let delay_ms = STORAGE_FLUSH_BASE_DELAY_MS << (attempt - 1);
                    warn!(
                        target: "domain_scanner::queue",
                        context = "scan_log",
                        scan_id = %scan_id,
                        error = %err,
                        attempt,
                        pending = pending.len(),
                        retry_delay_ms = delay_ms,
                        "scan log batch write failed; retaining it for retry"
                    );
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    attempt += 1;
                }
                Err(err) => return Err(err),
            }
        }
    }

    Ok(())
}

async fn persist_pending_log_batch(
    db: &SqlitePool,
    scan_stream: &broadcast::Sender<ScanStreamMessage>,
    scan_id: &str,
    pending: &mut Vec<PendingLogPersist>,
) -> Result<(), sqlx::Error> {
    if pending.is_empty() {
        return Ok(());
    }

    let batch_len = pending.len().min(LOG_FLUSH_BATCH_SIZE);
    let mut builder: QueryBuilder<'_, Sqlite> =
        QueryBuilder::new("INSERT INTO scan_logs (scan_id, level, message) ");
    builder.push_values(pending[..batch_len].iter(), |mut row, log| {
        row.push_bind(scan_id)
            .push_bind(&log.level)
            .push_bind(&log.message);
    });
    builder.push(" RETURNING id, message, level, created_at");

    let inserted = builder
        .build_query_as::<ScanLogEvent>()
        .fetch_all(db)
        .await?;

    pending.drain(..batch_len);
    for log in inserted {
        let _ = scan_stream.send(ScanStreamMessage::Log(log));
    }

    Ok(())
}

pub(super) fn rate_limited_service(res: &crate::DomainResult) -> Option<&'static str> {
    if res.trace.iter().any(|step| step.starts_with("WHOIS: ")) {
        return Some("whois");
    }
    if res.trace.iter().any(|step| step.starts_with("RDAP: ")) {
        return Some("rdap");
    }
    if res.trace.iter().any(|step| step.starts_with("DoH: ")) {
        return Some("doh");
    }

    let err = res.error.as_deref()?.to_ascii_uppercase();
    if err.contains("WHOIS") {
        Some("whois")
    } else if err.contains("RDAP") {
        Some("rdap")
    } else if err.contains("DOH") {
        Some("doh")
    } else {
        None
    }
}

#[cfg(test)]
mod persistence_tests {
    use super::*;

    fn pending_result(domain: &str) -> PendingResultPersist {
        PendingResultPersist {
            domain: domain.to_string(),
            registration_record_absent: true,
            purchasable: None,
            expiration_date: None,
            signatures: "WHOIS".to_string(),
        }
    }

    #[tokio::test]
    async fn result_batch_is_only_removed_after_successful_insert() {
        let db = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            "CREATE TABLE results (
                scan_id TEXT,
                domain TEXT,
                available BOOLEAN,
                registration_record_absent BOOLEAN,
                purchasable BOOLEAN,
                expiration_date TEXT,
                signatures TEXT,
                PRIMARY KEY (scan_id, domain)
            )",
        )
        .execute(&db)
        .await
        .unwrap();
        let (scan_stream, _) = broadcast::channel(4);
        let mut pending = vec![pending_result("example.test")];

        persist_pending_result_batch(&db, &scan_stream, "scan-1", &mut pending)
            .await
            .unwrap();

        assert!(pending.is_empty());
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM results")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn result_batch_is_retained_when_insert_fails() {
        let db = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let (scan_stream, _) = broadcast::channel(4);
        let mut pending = vec![pending_result("example.test")];

        let result = persist_pending_result_batch(&db, &scan_stream, "scan-1", &mut pending).await;

        assert!(result.is_err());
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].domain, "example.test");
    }

    #[tokio::test]
    async fn log_batch_is_retained_when_insert_fails() {
        let db = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let (scan_stream, _) = broadcast::channel(4);
        let mut pending = vec![PendingLogPersist {
            level: "ERROR".to_string(),
            message: "storage failure".to_string(),
        }];

        let result = persist_pending_log_batch(&db, &scan_stream, "scan-1", &mut pending).await;

        assert!(result.is_err());
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].message, "storage failure");
    }
}
