use sqlx::sqlite::SqlitePool;

pub(super) async fn scan_db() -> SqlitePool {
    let db = SqlitePool::connect("sqlite::memory:").await.unwrap();
    for statement in [
        "CREATE TABLE scans (id TEXT PRIMARY KEY, status TEXT, total INTEGER DEFAULT 0,
            processed INTEGER DEFAULT 0, found INTEGER DEFAULT 0, started_at TEXT,
            finished_at TEXT, retry_not_before INTEGER)",
        "CREATE TABLE results (scan_id TEXT, domain TEXT, available BOOLEAN,
            registration_record_absent BOOLEAN, purchasable BOOLEAN, expiration_date TEXT,
            signatures TEXT, PRIMARY KEY(scan_id, domain))",
        "CREATE TABLE scan_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT,
            level TEXT, message TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)",
        "CREATE TABLE scan_retries (scan_id TEXT, domain TEXT, attempt INTEGER,
            next_retry_at INTEGER, error TEXT, rate_limited BOOLEAN, retry_after_secs INTEGER,
            deferred BOOLEAN NOT NULL DEFAULT 0, resume_checker TEXT, PRIMARY KEY(scan_id, domain))",
        "INSERT INTO scans (id, status) VALUES ('scan-1', 'pending')",
    ] {
        sqlx::query(statement).execute(&db).await.unwrap();
    }
    super::db::create_candidate_tables(&db).await.unwrap();
    db
}
