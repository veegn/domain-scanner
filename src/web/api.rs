use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{
        IntoResponse,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use serde::Serialize;
use serde_json::json;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use crate::publish;

use super::dictionary::{self, RenameRequest};
use super::models::{
    AppState, MAX_DICTIONARY_PRODUCT, PublicPublishedScanSummary, PublishScanRequest,
    PublishedDomainHit, PublishedScanSummary, ReorderRequest, ScanLogEvent as LogRow,
    ScanResultEvent as ResultRow, ScanStatus, ScanStreamMessage, ScanSummary, StartScanRequest,
};

#[derive(Serialize)]
struct ApiError {
    error: String,
}

type ApiResponse = axum::response::Response;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/scans", get(get_scans))
        .route("/api/tlds", get(get_tlds))
        .route("/api/scans/stream", get(stream_scans))
        .route("/api/scan", post(start_scan))
        .route("/api/scan/:id", get(get_scan_status).delete(delete_scan))
        .route("/api/scan/:id/pause", post(pause_scan))
        .route("/api/scan/:id/resume", post(resume_scan))
        .route("/api/scan/:id/stream", get(stream_scan))
        .route("/api/scan/:id/results", get(get_results))
        .route("/api/scan/:id/logs", get(get_logs))
        .route("/api/scan/:id/publish", post(publish_scan))
        .route("/api/published", get(get_published_scans))
        .route(
            "/api/published/:id",
            get(get_published_scan)
                .put(update_published_scan)
                .delete(delete_published_scan),
        )
        .route("/api/public/published", get(get_public_published_scans))
        .route("/api/public/search", get(search_public_domains))
        .route("/api/scan/:id/reorder", post(reorder_scan))
        .route(
            "/api/settings",
            get(get_settings).put(update_settings),
        )
        .route("/api/dictionary", post(upload_dictionary))
        .route("/api/dictionaries", get(list_dictionaries))
        .route(
            "/api/dictionary/:id",
            get(get_dictionary)
                .put(rename_dictionary)
                .delete(delete_dictionary),
        )
        .route("/api/dictionary/:id/words", get(get_dictionary_words))
        .route("/api/rate_limits", get(get_rate_limits))
        .with_state(state)
}

#[derive(serde::Deserialize)]
struct PublicDomainSearchQuery {
    q: Option<String>,
    limit: Option<u32>,
}

#[derive(serde::Deserialize)]
struct ResultsQuery {
    offset: Option<i64>,
    limit: Option<i64>,
}

async fn start_scan(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<StartScanRequest>,
) -> ApiResponse {
    if let Err(e) = payload.validate() {
        return api_error(StatusCode::BAD_REQUEST, e);
    }

    // Validate multi-dictionary product against 2M cap
    if let Some(dict_ids) = &payload.dictionary_ids {
        if !dict_ids.is_empty() {
            let mut total: usize = 1;
            for dict_id in dict_ids {
                match dictionary::get_dictionary(&state.db, dict_id).await {
                    Ok(Some(d)) => {
                        let wc = d.word_count as usize;
                        total = total.saturating_mul(wc);
                        if total > MAX_DICTIONARY_PRODUCT {
                            break;
                        }
                    }
                    Ok(None) => {
                        return api_error(
                            StatusCode::BAD_REQUEST,
                            format!("Dictionary not found: {}", dict_id),
                        );
                    }
                    Err(e) => {
                        return api_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Failed to load dictionary {}: {}", dict_id, e),
                        );
                    }
                }
            }
            if total > MAX_DICTIONARY_PRODUCT {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    format!(
                        "Dictionary product {} exceeds maximum of {}",
                        total, MAX_DICTIONARY_PRODUCT
                    ),
                );
            }
        }
    }

    let scan_id = Uuid::new_v4().to_string();

    let priority_words_json =
        serde_json::to_string(&payload.priority_words).unwrap_or_else(|_| "null".to_string());
    let domains_json =
        serde_json::to_string(&payload.domains).unwrap_or_else(|_| "null".to_string());
    let dictionary_words_json =
        serde_json::to_string(&payload.dictionary_words).unwrap_or_else(|_| "null".to_string());
    let dictionary_ids_json =
        serde_json::to_string(&payload.dictionary_ids).unwrap_or_else(|_| "null".to_string());
    let scheduler_key = payload.scheduler_key();

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    if let Err(e) = sqlx::query("INSERT INTO scans (id, status, length, suffix, pattern, regex, scheduler_key) VALUES (?, 'pending', ?, ?, ?, ?, ?)")
        .bind(&scan_id)
        .bind(payload.length as i64)
        .bind(&payload.suffix)
        .bind(&payload.pattern)
        .bind(&payload.regex)
        .bind(&scheduler_key)
        .execute(&mut *tx)
        .await
    {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }

    if let Err(e) =
        sqlx::query("INSERT INTO scan_payloads (scan_id, priority_words, domains, dictionary_words, prefix, postfix, dictionary_id, dictionary_ids, separator, format_template) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(&scan_id)
            .bind(priority_words_json)
            .bind(domains_json)
            .bind(dictionary_words_json)
            .bind(&payload.prefix)
            .bind(&payload.postfix)
            .bind(&payload.dictionary_id)
            .bind(&dictionary_ids_json)
            .bind(&payload.separator)
            .bind(&payload.format_template)
            .execute(&mut *tx)
            .await
    {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }

    if let Err(e) = tx.commit().await {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }

    // Send wake up signal (non-blocking)
    let _ = state.task_tx.try_send(());
    state.streams.notify_scans();

    (StatusCode::ACCEPTED, Json(scan_id)).into_response()
}

async fn get_scan_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResponse {
    let row = match fetch_scan_status_row(&state.db, &id).await {
        Ok(row) => row,
        Err(e) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    match row {
        Some((id, status, total, processed, found)) => Json(ScanStatus {
            id,
            status,
            total,
            processed,
            found,
            deferred: 0,
        })
        .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn get_results(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<ResultsQuery>,
) -> ApiResponse {
    let offset = query.offset.unwrap_or(0).max(0);
    let limit = query.limit.unwrap_or(500).clamp(1, 5_000);
    let rows = match fetch_scan_results_page(&state.db, &id, offset, limit).await {
        Ok(rows) => rows,
        Err(e) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    Json(rows).into_response()
}

async fn get_scans(State(state): State<Arc<AppState>>) -> ApiResponse {
    let rows = match fetch_scan_summaries(&state.db).await {
        Ok(rows) => rows,
        Err(e) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    Json(rows).into_response()
}

async fn get_tlds(State(state): State<Arc<AppState>>) -> ApiResponse {
    let tlds = super::db::load_tlds(&state.db).await;
    Json(tlds).into_response()
}

async fn publish_scan(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(payload): Json<PublishScanRequest>,
) -> ApiResponse {
    if let Err(error) = payload.validate() {
        return api_error(StatusCode::BAD_REQUEST, error);
    }

    let scan_exists = match fetch_scan_exists(&state.db, &id).await {
        Ok(exists) => exists,
        Err(error) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
    };

    if !scan_exists {
        return StatusCode::NOT_FOUND.into_response();
    }

    match publish::create_published_scan(&state.db, &id, &payload).await {
        Ok(summary) => (StatusCode::CREATED, Json(summary)).into_response(),
        Err(error) => {
            let message = error.to_string();
            let status = if message.contains("scan not found") {
                StatusCode::NOT_FOUND
            } else if message.contains("publish title cannot be empty") {
                StatusCode::BAD_REQUEST
            } else if message.contains("only finished scans can be published") {
                StatusCode::CONFLICT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            api_error(status, message)
        }
    }
}

async fn get_published_scans(State(state): State<Arc<AppState>>) -> ApiResponse {
    match fetch_published_scan_summaries(&state.db).await {
        Ok(rows) => Json(rows).into_response(),
        Err(error) => api_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
    }
}

async fn get_published_scan(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResponse {
    match fetch_published_scan_summary_by_id(&state.db, &id).await {
        Ok(Some(row)) => Json(row).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => api_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
    }
}

async fn delete_published_scan(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResponse {
    match publish::delete_published_scan(&state.db, &id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => api_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
    }
}

async fn update_published_scan(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(payload): Json<PublishScanRequest>,
) -> ApiResponse {
    if let Err(error) = payload.validate() {
        return api_error(StatusCode::BAD_REQUEST, error);
    }

    match publish::update_published_scan(&state.db, &id, &payload).await {
        Ok(Some(summary)) => Json(summary).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            let message = error.to_string();
            let status = if message.contains("publish title cannot be empty") {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            api_error(status, message)
        }
    }
}

async fn get_public_published_scans(State(state): State<Arc<AppState>>) -> ApiResponse {
    match fetch_public_published_scan_summaries(&state.db).await {
        Ok(rows) => Json(rows).into_response(),
        Err(error) => api_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
    }
}

async fn search_public_domains(
    State(state): State<Arc<AppState>>,
    Query(query): Query<PublicDomainSearchQuery>,
) -> ApiResponse {
    let needle = query.q.unwrap_or_default().trim().to_string();
    if needle.is_empty() {
        return Json(Vec::<PublishedDomainHit>::new()).into_response();
    }
    if needle.len() > 253 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "search query must be at most 253 characters".to_string(),
        );
    }
    if !needle
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "search query may only contain letters, digits, '-' and '.'".to_string(),
        );
    }

    let limit = query.limit.unwrap_or(50).clamp(1, 1000) as i64;
    match fetch_public_domain_hits(&state.db, &needle, limit).await {
        Ok(rows) => Json(rows).into_response(),
        Err(error) => api_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
    }
}

async fn stream_scans(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let db = state.db.clone();
    let streams = state.streams.clone();
    let current_version = streams.current_scans_version();

    let stream = async_stream::stream! {
        let mut last_version = current_version;

        match fetch_scan_summaries(&db).await {
            Ok(rows) => {
                yield Ok::<Event, Infallible>(
                    Event::default()
                        .id(format_scans_event_id(current_version))
                        .event("scans")
                        .data(serde_json::to_string(&rows).unwrap_or_else(|_| "[]".to_string()))
                );
            }
            Err(err) => {
                yield Ok::<Event, Infallible>(
                    Event::default()
                        .event("error")
                        .data(json!({ "error": err.to_string() }).to_string())
                );
                return;
            }
        }

        let mut rx = streams.subscribe_scans();
        loop {
            match rx.recv().await {
                Ok(version) => {
                    if version <= last_version {
                        continue;
                    }
                    last_version = version;
                    match fetch_scan_summaries(&db).await {
                        Ok(rows) => {
                            yield Ok::<Event, Infallible>(
                                Event::default()
                                    .id(format_scans_event_id(version))
                                    .event("scans")
                                    .data(serde_json::to_string(&rows).unwrap_or_else(|_| "[]".to_string()))
                            );
                        }
                        Err(err) => {
                            yield Ok::<Event, Infallible>(
                                Event::default()
                                    .event("error")
                                    .data(json!({ "error": err.to_string() }).to_string())
                            );
                            break;
                        }
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            }
        }
    };

    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keep-alive"),
        )
        .into_response()
}

async fn get_logs(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> impl IntoResponse {
    let rows = match fetch_scan_logs(&state.db, &id, 0).await {
        Ok(rows) => rows.into_iter().rev().collect::<Vec<_>>(),
        Err(e) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    Json(rows).into_response()
}

async fn stream_scan(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let db = state.db.clone();
    let streams = state.streams.clone();
    let (mut log_cursor, mut result_cursor) = parse_scan_event_id(
        headers
            .get("last-event-id")
            .and_then(|value| value.to_str().ok()),
    );

    let stream = async_stream::stream! {
        match sqlx::query_as::<_, (String, String, i64, i64, i64)>(
            "SELECT id, status, total, processed, found FROM scans WHERE id = ?",
        )
        .bind(&id)
        .fetch_optional(&db)
        .await
        {
            Ok(Some((scan_id, status, total, processed, found))) => {
                yield Ok::<Event, Infallible>(
                    sse_event(
                        "status",
                        format_scan_event_id(log_cursor, result_cursor),
                        json!({
                            "id": scan_id,
                            "status": status,
                            "total": total,
                            "processed": processed,
                            "found": found,
                        }),
                    )
                );
            }
            Ok(None) => {
                yield Ok::<Event, Infallible>(
                    sse_event_without_id("deleted", json!({ "id": id }))
                );
                return;
            }
            Err(err) => {
                yield Ok::<Event, Infallible>(
                    sse_event_without_id("error", json!({ "error": err.to_string() }))
                );
                return;
            }
        }

        match fetch_scan_logs(&db, &id, log_cursor).await {
            Ok(rows) => {
                for log in rows {
                    log_cursor = log.id.max(log_cursor);
                    yield Ok::<Event, Infallible>(
                        sse_serialized_event("log", format_scan_event_id(log_cursor, result_cursor), &log)
                    );
                }
            }
            Err(err) => {
                yield Ok::<Event, Infallible>(
                    sse_event_without_id("error", json!({ "error": err.to_string() }))
                );
                return;
            }
        }

        match fetch_scan_results(&db, &id, result_cursor).await {
            Ok(rows) => {
                for batch in rows.chunks(100) {
                    if let Some(last) = batch.last() {
                        result_cursor = result_cursor.max(last.event_id);
                    }
                    yield Ok::<Event, Infallible>(
                        sse_serialized_event(
                            "result_batch",
                            format_scan_event_id(log_cursor, result_cursor),
                            batch,
                        )
                    );
                }
            }
            Err(err) => {
                yield Ok::<Event, Infallible>(
                    sse_event_without_id("error", json!({ "error": err.to_string() }))
                );
                return;
            }
        }

        let mut rx = streams.subscribe_scan(&id).await;
        let mut pending: Option<ScanStreamMessage> = None;
        loop {
            let next = if let Some(message) = pending.take() {
                Ok(message)
            } else {
                rx.recv().await
            };

            match next {
                Ok(ScanStreamMessage::Status(status)) => {
                    yield Ok::<Event, Infallible>(
                        sse_serialized_event(
                            "status",
                            format_scan_event_id(log_cursor, result_cursor),
                            &status,
                        )
                    );
                }
                Ok(ScanStreamMessage::Log(log)) => {
                    log_cursor = log_cursor.max(log.id);
                    yield Ok::<Event, Infallible>(
                        sse_serialized_event("log", format_scan_event_id(log_cursor, result_cursor), &log)
                    );
                }
                Ok(ScanStreamMessage::Result(result)) => {
                    let mut batch = vec![result];
                    loop {
                        match rx.try_recv() {
                            Ok(ScanStreamMessage::Result(result)) => batch.push(result),
                            Ok(other) => {
                                pending = Some(other);
                                break;
                            }
                            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
                            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => continue,
                            Err(tokio::sync::broadcast::error::TryRecvError::Closed) => break,
                        }
                    }
                    if let Some(last) = batch.last() {
                        result_cursor = result_cursor.max(last.event_id);
                    }
                    yield Ok::<Event, Infallible>(
                        sse_serialized_event(
                            "result_batch",
                            format_scan_event_id(log_cursor, result_cursor),
                            &batch,
                        )
                    );
                }
                Ok(ScanStreamMessage::Deleted(scan_id)) => {
                    yield Ok::<Event, Infallible>(
                        sse_event(
                            "deleted",
                            format_scan_event_id(log_cursor, result_cursor),
                            json!({ "id": scan_id }),
                        )
                    );
                    break;
                }
                Ok(ScanStreamMessage::Complete(scan_id)) => {
                    yield Ok::<Event, Infallible>(
                        sse_event(
                            "complete",
                            format_scan_event_id(log_cursor, result_cursor),
                            json!({ "id": scan_id }),
                        )
                    );
                    break;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            }
        }
    };

    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keep-alive"),
        )
        .into_response()
}

async fn fetch_scan_summaries(db: &sqlx::SqlitePool) -> Result<Vec<ScanSummary>, sqlx::Error> {
    sqlx::query_as::<_, ScanSummary>(
        "SELECT s.id,
                s.status,
                s.length,
                s.suffix,
                s.pattern,
                s.regex,
                CASE
                    WHEN p.domains IS NOT NULL AND p.domains != 'null' AND p.domains != '[]' THEN 1
                    ELSE 0
                END AS has_domains,
                CASE
                    WHEN (p.dictionary_ids IS NOT NULL AND p.dictionary_ids != 'null' AND p.dictionary_ids != '[]')
                      OR (p.dictionary_id IS NOT NULL AND p.dictionary_id != 'null')
                      OR (p.dictionary_words IS NOT NULL AND p.dictionary_words != 'null' AND p.dictionary_words != '[]')
                    THEN 1
                    ELSE 0
                END AS has_dictionary,
                s.priority,
                s.total,
                s.processed,
                s.found,
                s.created_at,
                s.started_at,
                s.finished_at
         FROM scans s
         LEFT JOIN scan_payloads p ON s.id = p.scan_id
         ORDER BY CASE s.status
                    WHEN 'running' THEN 0
                    WHEN 'pausing' THEN 1
                    WHEN 'cancelling' THEN 2
                    WHEN 'paused' THEN 3
                    WHEN 'pending' THEN 4
                    WHEN 'failed' THEN 5
                    WHEN 'finished' THEN 6
                    WHEN 'cancelled' THEN 7
                    ELSE 8
                  END,
                  CASE WHEN s.status = 'pending' THEN s.priority ELSE 0 END DESC,
                  CASE WHEN s.status = 'pending' THEN s.created_at END ASC,
                  COALESCE(s.finished_at, s.started_at, s.created_at) DESC
         LIMIT 60",
    )
    .fetch_all(db)
    .await
}

async fn fetch_scan_status_row(
    db: &sqlx::SqlitePool,
    id: &str,
) -> Result<Option<(String, String, i64, i64, i64)>, sqlx::Error> {
    sqlx::query_as::<_, (String, String, i64, i64, i64)>(
        "SELECT id, status, total, processed, found FROM scans WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db)
    .await
}

async fn fetch_scan_exists(db: &sqlx::SqlitePool, id: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM scans WHERE id = ?")
        .bind(id)
        .fetch_one(db)
        .await
        .map(|count| count > 0)
}

async fn fetch_scan_logs(
    db: &sqlx::SqlitePool,
    id: &str,
    after_id: i64,
) -> Result<Vec<LogRow>, sqlx::Error> {
    sqlx::query_as::<_, LogRow>(
        "SELECT id, message, level, created_at
         FROM scan_logs
         WHERE scan_id = ? AND id > ?
         ORDER BY id ASC
         LIMIT 200",
    )
    .bind(id)
    .bind(after_id)
    .fetch_all(db)
    .await
}

async fn fetch_scan_results(
    db: &sqlx::SqlitePool,
    id: &str,
    after_event_id: i64,
) -> Result<Vec<ResultRow>, sqlx::Error> {
    sqlx::query_as::<_, ResultRow>(
        "SELECT rowid as event_id, domain, available, expiration_date, signatures
         FROM results
         WHERE scan_id = ? AND available = 1 AND rowid > ?
         ORDER BY rowid ASC",
    )
    .bind(id)
    .bind(after_event_id)
    .fetch_all(db)
    .await
}

async fn fetch_scan_results_page(
    db: &sqlx::SqlitePool,
    id: &str,
    offset: i64,
    limit: i64,
) -> Result<Vec<ResultRow>, sqlx::Error> {
    sqlx::query_as::<_, ResultRow>(
        "SELECT rowid as event_id, domain, available, expiration_date, signatures
         FROM results
         WHERE scan_id = ? AND available = 1
         ORDER BY rowid ASC
         LIMIT ? OFFSET ?",
    )
    .bind(id)
    .bind(limit)
    .bind(offset)
    .fetch_all(db)
    .await
}

async fn fetch_published_scan_summaries(
    db: &sqlx::SqlitePool,
) -> Result<Vec<PublishedScanSummary>, sqlx::Error> {
    sqlx::query_as::<_, PublishedScanSummary>(
        "SELECT id, scan_id, slug, title, description, status, result_count, published_at, updated_at
         FROM published_scans
         ORDER BY published_at DESC, updated_at DESC",
    )
    .fetch_all(db)
    .await
}

async fn fetch_published_scan_summary_by_id(
    db: &sqlx::SqlitePool,
    id: &str,
) -> Result<Option<PublishedScanSummary>, sqlx::Error> {
    sqlx::query_as::<_, PublishedScanSummary>(
        "SELECT id, scan_id, slug, title, description, status, result_count, published_at, updated_at
         FROM published_scans
         WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db)
    .await
}

async fn fetch_public_published_scan_summaries(
    db: &sqlx::SqlitePool,
) -> Result<Vec<PublicPublishedScanSummary>, sqlx::Error> {
    sqlx::query_as::<_, PublicPublishedScanSummary>(
        "SELECT ps.slug,
                ps.title,
                ps.description,
                s.suffix,
                s.pattern,
                s.length,
                ps.result_count,
                ps.published_at,
                s.finished_at as scan_finished_at
         FROM published_scans ps
         JOIN scans s ON s.id = ps.scan_id
         WHERE ps.status = 'active'
         ORDER BY ps.published_at DESC, ps.updated_at DESC",
    )
    .fetch_all(db)
    .await
}

async fn fetch_public_domain_hits(
    db: &sqlx::SqlitePool,
    needle: &str,
    limit: i64,
) -> Result<Vec<PublishedDomainHit>, sqlx::Error> {
    let pattern = format!("{needle}%");
    sqlx::query_as::<_, PublishedDomainHit>(
        "SELECT pd.domain,
                pd.available,
                pd.expiration_date,
                pd.signatures,
                pd.published_at,
                s.finished_at as scan_finished_at,
                ps.slug,
                ps.title
         FROM published_domains pd
         JOIN published_scans ps ON ps.id = pd.published_scan_id
         JOIN scans s ON s.id = ps.scan_id
         WHERE ps.status = 'active'
           AND pd.domain LIKE ? COLLATE NOCASE
         ORDER BY ps.published_at DESC, pd.domain ASC
         LIMIT ?",
    )
    .bind(pattern)
    .bind(limit)
    .fetch_all(db)
    .await
}

fn api_error(status: StatusCode, error: String) -> ApiResponse {
    (status, Json(ApiError { error })).into_response()
}

fn sse_event<T: Serialize>(event: &str, id: String, payload: T) -> Event {
    Event::default()
        .id(id)
        .event(event)
        .data(serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string()))
}

fn sse_event_without_id<T: Serialize>(event: &str, payload: T) -> Event {
    Event::default()
        .event(event)
        .data(serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string()))
}

fn sse_serialized_event<T: Serialize + ?Sized>(event: &str, id: String, payload: &T) -> Event {
    sse_event(event, id, payload)
}

fn format_scans_event_id(version: u64) -> String {
    format!("v:{version}")
}

fn format_scan_event_id(log_id: i64, result_id: i64) -> String {
    format!("l:{log_id};r:{result_id}")
}

fn parse_scan_event_id(value: Option<&str>) -> (i64, i64) {
    let mut log_id = 0_i64;
    let mut result_id = 0_i64;

    if let Some(value) = value {
        for part in value.split(';') {
            if let Some(raw) = part.strip_prefix("l:") {
                log_id = raw.parse::<i64>().unwrap_or(0);
            } else if let Some(raw) = part.strip_prefix("r:") {
                result_id = raw.parse::<i64>().unwrap_or(0);
            }
        }
    }

    (log_id.max(0), result_id.max(0))
}

async fn reorder_scan(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(payload): Json<ReorderRequest>,
) -> impl IntoResponse {
    if payload.direction != "up" && payload.direction != "down" {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                error: "direction must be 'up' or 'down'".to_string(),
            }),
        )
            .into_response();
    }

    let increment: i64 = if payload.direction == "up" { 1 } else { -1 };
    match sqlx::query("UPDATE scans SET priority = priority + ? WHERE id = ?")
        .bind(increment)
        .bind(&id)
        .execute(&state.db)
        .await
    {
        Ok(result) if result.rows_affected() > 0 => {
            let _ = state.task_tx.try_send(());
            state.streams.notify_scans();
            StatusCode::OK.into_response()
        }
        Ok(_) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn delete_scan(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Query status and real counters together to avoid a second round-trip when
    // pushing the `cancelling` Status event.
    let row = match sqlx::query_as::<_, (String, i64, i64, i64)>(
        "SELECT status, total, processed, found FROM scans WHERE id = ?",
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: e.to_string(),
                }),
            )
                .into_response();
        }
    };
    let (status, total, processed, found) = row;
    let has_live_task = state.task_control.contains(&id);

    if matches!(status.as_str(), "running" | "pausing" | "cancelling") {
        if has_live_task {
            state.task_control.cancel(&id);
        }
        let next_status = if has_live_task {
            "cancelling"
        } else {
            "cancelled"
        };
        match sqlx::query("UPDATE scans SET status = ?, finished_at = CASE WHEN ? = 'cancelled' THEN COALESCE(finished_at, CURRENT_TIMESTAMP) ELSE finished_at END WHERE id = ?")
            .bind(next_status)
            .bind(next_status)
            .bind(&id)
            .execute(&state.db)
            .await
        {
            Ok(_) => {
                state.streams.notify_scans();
                state
                    .streams
                    .publish_scan(
                        &id,
                        ScanStreamMessage::Status(ScanStatus {
                            id: id.clone(),
                            status: next_status.to_string(),
                            total,
                            processed,
                            found,
                            deferred: 0,
                        }),
                    )
                    .await;
                if has_live_task {
                    StatusCode::ACCEPTED.into_response()
                } else {
                    StatusCode::OK.into_response()
                }
            }
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: e.to_string(),
                }),
            )
                .into_response(),
        }
    } else {
        match sqlx::query("DELETE FROM scans WHERE id = ?")
            .bind(&id)
            .execute(&state.db)
            .await
        {
            Ok(_) => {
                state.streams.notify_scans();
                state
                    .streams
                    .publish_scan(&id, ScanStreamMessage::Deleted(id.clone()))
                    .await;
                // Clean up the broadcast channel now that no more messages will be sent.
                state.streams.cleanup_scan(&id).await;
                StatusCode::OK.into_response()
            }
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: e.to_string(),
                }),
            )
                .into_response(),
        }
    }
}

async fn pause_scan(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let row = match fetch_scan_status_row(&state.db, &id).await {
        Ok(Some(row)) => row,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: e.to_string(),
                }),
            )
                .into_response();
        }
    };
    let (_, status, total, processed, found) = row;

    if status == "paused" {
        return StatusCode::NO_CONTENT.into_response();
    }

    if status != "running" {
        return api_error(
            StatusCode::CONFLICT,
            format!("scan cannot be paused from status '{status}'"),
        );
    }

    if !state.task_control.pause(&id) {
        return api_error(
            StatusCode::CONFLICT,
            "scan is not actively running in the worker".to_string(),
        );
    }

    match sqlx::query("UPDATE scans SET status = 'pausing' WHERE id = ?")
        .bind(&id)
        .execute(&state.db)
        .await
    {
        Ok(_) => {
            state.streams.notify_scans();
            state
                .streams
                .publish_scan(
                    &id,
                    ScanStreamMessage::Status(ScanStatus {
                        id: id.clone(),
                        status: "pausing".to_string(),
                        total,
                        processed,
                        found,
                        deferred: 0,
                    }),
                )
                .await;
            StatusCode::ACCEPTED.into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn resume_scan(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let row = match fetch_scan_status_row(&state.db, &id).await {
        Ok(Some(row)) => row,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: e.to_string(),
                }),
            )
                .into_response();
        }
    };
    let (_, status, total, processed, found) = row;

    if status == "pending" || status == "running" {
        return StatusCode::NO_CONTENT.into_response();
    }

    if status != "paused" {
        return api_error(
            StatusCode::CONFLICT,
            format!("scan cannot be resumed from status '{status}'"),
        );
    }

    match sqlx::query("UPDATE scans SET status = 'pending', retry_not_before = NULL WHERE id = ?")
        .bind(&id)
        .execute(&state.db)
        .await
    {
        Ok(_) => {
            let _ = state.task_tx.try_send(());
            state.streams.notify_scans();
            state
                .streams
                .publish_scan(
                    &id,
                    ScanStreamMessage::Status(ScanStatus {
                        id: id.clone(),
                        status: "pending".to_string(),
                        total,
                        processed,
                        found,
                        deferred: 0,
                    }),
                )
                .await;
            StatusCode::ACCEPTED.into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

// --- Dictionary management handlers ---

#[derive(serde::Deserialize)]
struct DictionaryUploadQuery {
    name: Option<String>,
}

async fn upload_dictionary(
    State(state): State<Arc<AppState>>,
    Query(params): Query<DictionaryUploadQuery>,
    body: Bytes,
) -> ApiResponse {
    let name = params.name.unwrap_or_default().trim().to_string();
    if name.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "dictionary name is required".to_string(),
        );
    }
    if body.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "dictionary body cannot be empty".to_string(),
        );
    }

    match dictionary::create_dictionary(&state.db, &name, &body).await {
        Ok(summary) => (StatusCode::CREATED, Json(summary)).into_response(),
        Err(error) => {
            let msg = error.to_string();
            let status = if msg.contains("too many") {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            api_error(status, msg)
        }
    }
}

async fn list_dictionaries(State(state): State<Arc<AppState>>) -> ApiResponse {
    match dictionary::list_dictionaries(&state.db).await {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn get_dictionary(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> ApiResponse {
    match dictionary::get_dictionary(&state.db, &id).await {
        Ok(Some(detail)) => Json(detail).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn rename_dictionary(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(payload): Json<RenameRequest>,
) -> ApiResponse {
    if payload.name.trim().is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "name cannot be empty".to_string());
    }
    match dictionary::rename_dictionary(&state.db, &id, payload.name.trim()).await {
        Ok(Some(summary)) => Json(summary).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn delete_dictionary(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResponse {
    match dictionary::delete_dictionary(&state.db, &id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

#[derive(serde::Deserialize)]
struct WordPreviewQuery {
    offset: Option<usize>,
    limit: Option<usize>,
}

async fn get_dictionary_words(
    Path(id): Path<String>,
    Query(query): Query<WordPreviewQuery>,
) -> ApiResponse {
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(100).min(1000);
    match dictionary::get_dictionary_words(&id, offset, limit).await {
        Ok(words) => Json(words).into_response(),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

#[derive(serde::Serialize)]
struct RateLimitStatus {
    service: String,
    endpoint: String,
    cooldown_remaining_secs: u64,
}

async fn get_rate_limits() -> ApiResponse {
    let mut limits = Vec::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if let Ok(content) = std::fs::read_to_string("data/cache/rdap/rate_limits.json") {
        if let Ok(cache) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(endpoints) = cache.get("endpoints").and_then(|v| v.as_object()) {
                for (k, v) in endpoints {
                    if let Some(cooldown) = v.get("cooldown_until_epoch_secs").and_then(|v| v.as_u64()) {
                        if cooldown > now {
                            limits.push(RateLimitStatus {
                                service: "RDAP".to_string(),
                                endpoint: k.clone(),
                                cooldown_remaining_secs: cooldown - now,
                            });
                        }
                    }
                }
            }
        }
    }

    if let Ok(content) = std::fs::read_to_string("data/cache/whois/rate_limits.json") {
        if let Ok(cache) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(servers) = cache.get("servers").and_then(|v| v.as_object()) {
                for (k, v) in servers {
                    if let Some(cooldown) = v.get("cooldown_until_epoch_secs").and_then(|v| v.as_u64()) {
                        if cooldown > now {
                            limits.push(RateLimitStatus {
                                service: "WHOIS".to_string(),
                                endpoint: k.clone(),
                                cooldown_remaining_secs: cooldown - now,
                            });
                        }
                    }
                }
            }
        }
    }

    Json(limits).into_response()
}

async fn get_settings(State(state): State<Arc<AppState>>) -> ApiResponse {
    match crate::web::load_app_config(&state.db).await {
        Ok(Some(config)) => Json(config).into_response(),
        Ok(None) => Json(crate::config::AppConfig::default()).into_response(),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn update_settings(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<crate::config::AppConfig>,
) -> ApiResponse {
    match crate::web::save_app_config(&state.db, &payload).await {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}
