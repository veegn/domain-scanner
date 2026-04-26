use sqlx::{Row, sqlite::SqlitePool};
use tracing::{error, warn};

#[derive(Debug, Default)]
pub struct StartupRecovery {
    pub recovered_cancelling: u64,
    pub recovered_pausing: u64,
    pub repaired_counters: u64,
    pub ready_scan_ids: Vec<String>,
}

impl StartupRecovery {
    pub fn should_wake_worker(&self) -> bool {
        !self.ready_scan_ids.is_empty()
    }
}

pub async fn recover_startup_tasks(db: &SqlitePool) -> StartupRecovery {
    let recovered_cancelling = mark_stale_cancelling_as_cancelled(db).await;
    let recovered_pausing = mark_stale_pausing_as_paused(db).await;
    let repaired_counters = repair_scan_counters(db).await;
    let ready_scan_ids = fetch_ready_scan_ids(db).await;

    StartupRecovery {
        recovered_cancelling,
        recovered_pausing,
        repaired_counters,
        ready_scan_ids,
    }
}

async fn mark_stale_cancelling_as_cancelled(db: &SqlitePool) -> u64 {
    match sqlx::query(
        "UPDATE scans
         SET status = 'cancelled',
             finished_at = COALESCE(finished_at, CURRENT_TIMESTAMP)
         WHERE status = 'cancelling'",
    )
    .execute(db)
    .await
    {
        Ok(result) => result.rows_affected(),
        Err(err) => {
            error!(
                target: "domain_scanner::recovery",
                context = "startup",
                error = %err,
                "failed to recover stale cancelling scans"
            );
            0
        }
    }
}

async fn mark_stale_pausing_as_paused(db: &SqlitePool) -> u64 {
    match sqlx::query(
        "UPDATE scans
         SET status = 'paused',
             retry_not_before = NULL
         WHERE status = 'pausing'",
    )
    .execute(db)
    .await
    {
        Ok(result) => result.rows_affected(),
        Err(err) => {
            error!(
                target: "domain_scanner::recovery",
                context = "startup",
                error = %err,
                "failed to recover stale pausing scans"
            );
            0
        }
    }
}

async fn repair_scan_counters(db: &SqlitePool) -> u64 {
    match sqlx::query(
        "UPDATE scans
         SET processed = (
                 SELECT COUNT(*)
                 FROM results r
                 WHERE r.scan_id = scans.id
             ),
             found = (
                 SELECT COALESCE(SUM(CASE WHEN r.available = 1 THEN 1 ELSE 0 END), 0)
                 FROM results r
                 WHERE r.scan_id = scans.id
             )
         WHERE processed != (
                 SELECT COUNT(*)
                 FROM results r
                 WHERE r.scan_id = scans.id
             )
            OR found != (
                 SELECT COALESCE(SUM(CASE WHEN r.available = 1 THEN 1 ELSE 0 END), 0)
                 FROM results r
                 WHERE r.scan_id = scans.id
             )",
    )
    .execute(db)
    .await
    {
        Ok(result) => result.rows_affected(),
        Err(err) => {
            error!(
                target: "domain_scanner::recovery",
                context = "startup",
                error = %err,
                "failed to repair scan counters"
            );
            0
        }
    }
}

async fn fetch_ready_scan_ids(db: &SqlitePool) -> Vec<String> {
    match sqlx::query(
        "SELECT id
         FROM scans
         WHERE status IN ('pending', 'running')
           AND (retry_not_before IS NULL OR retry_not_before <= strftime('%s','now'))
         ORDER BY priority DESC, created_at ASC",
    )
    .fetch_all(db)
    .await
    {
        Ok(rows) => rows
            .into_iter()
            .filter_map(|row| row.try_get::<String, _>("id").ok())
            .collect(),
        Err(err) => {
            warn!(
                target: "domain_scanner::recovery",
                context = "startup",
                error = %err,
                "failed to query ready startup tasks"
            );
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            "CREATE TABLE scans (
                id TEXT PRIMARY KEY,
                status TEXT,
                processed INTEGER DEFAULT 0,
                found INTEGER DEFAULT 0,
                priority INTEGER DEFAULT 0,
                retry_not_before INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                finished_at DATETIME
            )",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "CREATE TABLE results (
                scan_id TEXT,
                domain TEXT,
                available BOOLEAN
            )",
        )
        .execute(&pool)
        .await
        .unwrap();

        pool
    }

    #[tokio::test]
    async fn recovery_normalizes_transient_statuses_and_repairs_counters() {
        let pool = setup_pool().await;

        sqlx::query(
            "INSERT INTO scans (id, status, processed, found, priority)
             VALUES
                ('cancel-1', 'cancelling', 5, 1, 0),
                ('pause-1', 'pausing', 2, 1, 0),
                ('run-1', 'running', 99, 99, 2),
                ('pending-1', 'pending', 0, 0, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO results (scan_id, domain, available)
             VALUES
                ('run-1', 'a.test', 1),
                ('run-1', 'b.test', 0),
                ('pause-1', 'c.test', 1)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let recovery = recover_startup_tasks(&pool).await;

        assert_eq!(recovery.recovered_cancelling, 1);
        assert_eq!(recovery.recovered_pausing, 1);
        assert_eq!(recovery.repaired_counters, 3);
        assert_eq!(recovery.ready_scan_ids, vec!["run-1", "pending-1"]);

        let cancel_status: String =
            sqlx::query_scalar("SELECT status FROM scans WHERE id = 'cancel-1'")
                .fetch_one(&pool)
                .await
                .unwrap();
        let pause_status: String =
            sqlx::query_scalar("SELECT status FROM scans WHERE id = 'pause-1'")
                .fetch_one(&pool)
                .await
                .unwrap();
        let run_counts: (i64, i64) =
            sqlx::query_as("SELECT processed, found FROM scans WHERE id = 'run-1'")
                .fetch_one(&pool)
                .await
                .unwrap();

        assert_eq!(cancel_status, "cancelled");
        assert_eq!(pause_status, "paused");
        assert_eq!(run_counts, (2, 1));
    }
}
