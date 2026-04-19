use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde::Serialize;
use std::sync::Arc;
use uuid::Uuid;

use super::models::{AppState, ReorderRequest, ScanStatus, StartScanRequest};

#[derive(Serialize)]
struct ApiError {
    error: String,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/scans", get(get_scans))
        .route("/api/scan", post(start_scan))
        .route("/api/scan/:id", get(get_scan_status).delete(delete_scan))
        .route("/api/scan/:id/results", get(get_results))
        .route("/api/scan/:id/logs", get(get_logs))
        .route("/api/scan/:id/reorder", post(reorder_scan))
        .with_state(state)
}

async fn start_scan(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<StartScanRequest>,
) -> impl IntoResponse {
    if let Err(e) = payload.validate() {
        return (StatusCode::BAD_REQUEST, Json(ApiError { error: e })).into_response();
    }

    let scan_id = Uuid::new_v4().to_string();

    let priority_words_json =
        serde_json::to_string(&payload.priority_words).unwrap_or_else(|_| "null".to_string());
    let domains_json =
        serde_json::to_string(&payload.domains).unwrap_or_else(|_| "null".to_string());

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
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

    if let Err(e) = sqlx::query("INSERT INTO scans (id, status, length, suffix, pattern, regex) VALUES (?, 'pending', ?, ?, ?, ?)")
        .bind(&scan_id)
        .bind(payload.length as i64)
        .bind(&payload.suffix)
        .bind(&payload.pattern)
        .bind(&payload.regex)
        .execute(&mut *tx)
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                error: e.to_string(),
            }),
        )
            .into_response();
        }

    if let Err(e) =
        sqlx::query("INSERT INTO scan_payloads (scan_id, priority_words, domains) VALUES (?, ?, ?)")
            .bind(&scan_id)
            .bind(priority_words_json)
            .bind(domains_json)
            .execute(&mut *tx)
            .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                error: e.to_string(),
            }),
        )
            .into_response();
    }

    if let Err(e) = tx.commit().await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                error: e.to_string(),
            }),
        )
            .into_response();
    }

    // Send wake up signal (non-blocking)
    let _ = state.task_tx.try_send(());

    (StatusCode::ACCEPTED, Json(scan_id)).into_response()
}

async fn get_scan_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let row = match sqlx::query_as::<_, (String, String, i64, i64, i64)>(
        "SELECT id, status, total, processed, found FROM scans WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    {
        Ok(row) => row,
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

    match row {
        Some((id, status, total, processed, found)) => Json(ScanStatus {
            id,
            status,
            total,
            processed,
            found,
        })
        .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn get_results(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    #[derive(Serialize, sqlx::FromRow)]
    struct ResultRow {
        domain: String,
        available: bool,
        expiration_date: Option<String>,
        signatures: String,
    }

    let rows = match sqlx::query_as::<_, ResultRow>("SELECT domain, available, expiration_date, signatures FROM results WHERE scan_id = ? AND available = 1")
        .bind(id)
        .fetch_all(&state.db)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: e.to_string(),
                }),
            )
                .into_response()
        }
    };

    Json(rows).into_response()
}

async fn get_scans(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    #[derive(Serialize, sqlx::FromRow)]
    struct ScanSummary {
        id: String,
        status: String,
        length: i64,
        suffix: String,
        pattern: String,
        regex: Option<String>,
        has_domains: bool,
        total: i64,
        processed: i64,
        found: i64,
        finished_at: Option<String>,
    }

    let rows = match sqlx::query_as::<_, ScanSummary>(
        "SELECT s.id,
                s.status,
                s.length,
                s.suffix,
                s.pattern,
                s.regex,
                CASE
                    WHEN p.domains IS NOT NULL AND p.domains != 'null' THEN 1
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
    .fetch_all(&state.db)
    .await
    {
        Ok(rows) => rows,
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

    Json(rows).into_response()
}

async fn get_logs(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> impl IntoResponse {
    #[derive(Serialize, sqlx::FromRow)]
    struct LogRow {
        id: i64,
        message: String,
        level: String,
        created_at: String,
    }

    let rows = match sqlx::query_as::<_, LogRow>(
        "SELECT id, message, level, created_at FROM scan_logs WHERE scan_id = ? ORDER BY id DESC LIMIT 200"
    )
    .bind(id)
    .fetch_all(&state.db)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: e.to_string(),
                }),
            )
                .into_response()
        }
    };

    Json(rows).into_response()
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
        .bind(id)
        .execute(&state.db)
        .await
    {
        Ok(result) if result.rows_affected() > 0 => {
            let _ = state.task_tx.try_send(());
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
    let status = match sqlx::query_scalar::<_, String>("SELECT status FROM scans WHERE id = ?")
        .bind(&id)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(status)) => status,
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

    if matches!(status.as_str(), "running" | "cancelling") {
        state.task_control.cancel(&id);
        match sqlx::query("UPDATE scans SET status = 'cancelling' WHERE id = ?")
            .bind(&id)
            .execute(&state.db)
            .await
        {
            Ok(_) => StatusCode::ACCEPTED.into_response(),
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
            .bind(id)
            .execute(&state.db)
            .await
        {
            Ok(_) => StatusCode::OK.into_response(),
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
