use axum::{
    Json, Router,
    extract::{Path, State},
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

use super::models::{
    AppState, ReorderRequest, ScanLogEvent as LogRow, ScanResultEvent as ResultRow, ScanStatus,
    ScanStreamMessage, ScanSummary, StartScanRequest,
};

#[derive(Serialize)]
struct ApiError {
    error: String,
}

type ApiResponse = axum::response::Response;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/scans", get(get_scans))
        .route("/api/scans/stream", get(stream_scans))
        .route("/api/scan", post(start_scan))
        .route("/api/scan/:id", get(get_scan_status).delete(delete_scan))
        .route("/api/scan/:id/stream", get(stream_scan))
        .route("/api/scan/:id/results", get(get_results))
        .route("/api/scan/:id/logs", get(get_logs))
        .route("/api/scan/:id/reorder", post(reorder_scan))
        .with_state(state)
}

async fn start_scan(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<StartScanRequest>,
) -> ApiResponse {
    if let Err(e) = payload.validate() {
        return api_error(StatusCode::BAD_REQUEST, e);
    }

    let scan_id = Uuid::new_v4().to_string();

    let priority_words_json =
        serde_json::to_string(&payload.priority_words).unwrap_or_else(|_| "null".to_string());
    let domains_json =
        serde_json::to_string(&payload.domains).unwrap_or_else(|_| "null".to_string());

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    if let Err(e) = sqlx::query("INSERT INTO scans (id, status, length, suffix, pattern, regex) VALUES (?, 'pending', ?, ?, ?, ?)")
        .bind(&scan_id)
        .bind(payload.length as i64)
        .bind(&payload.suffix)
        .bind(&payload.pattern)
        .bind(&payload.regex)
        .execute(&mut *tx)
        .await
    {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }

    if let Err(e) =
        sqlx::query("INSERT INTO scan_payloads (scan_id, priority_words, domains) VALUES (?, ?, ?)")
            .bind(&scan_id)
            .bind(priority_words_json)
            .bind(domains_json)
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

async fn get_results(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> ApiResponse {
    let rows = match fetch_scan_results(&state.db, &id, 0).await {
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
                s.total,
                s.processed,
                s.found,
                s.finished_at
         FROM scans s
         LEFT JOIN scan_payloads p ON s.id = p.scan_id
         ORDER BY COALESCE(s.finished_at, s.started_at, s.created_at) DESC
         LIMIT 20",
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

    if matches!(status.as_str(), "running" | "cancelling") {
        state.task_control.cancel(&id);
        match sqlx::query("UPDATE scans SET status = 'cancelling' WHERE id = ?")
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
                            status: "cancelling".to_string(),
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
