use sqlx::sqlite::SqlitePool;
use std::collections::HashMap;

const SEED_SQL: &str = include_str!("../../data/seed.sql");

pub async fn init_db() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite:scans.db?mode=rwc")
        .await
        .unwrap();

    let _ = sqlx::query("PRAGMA foreign_keys = ON;")
        .execute(&pool)
        .await;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            status TEXT,
            length INTEGER,
            suffix TEXT,
            pattern TEXT,
            regex TEXT,
            total INTEGER DEFAULT 0,
            processed INTEGER DEFAULT 0,
            found INTEGER DEFAULT 0,
            priority INTEGER DEFAULT 0,
            retry_not_before INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            started_at DATETIME,
            finished_at DATETIME
        )",
    )
    .execute(&pool)
    .await
    .unwrap();
    let _ = sqlx::query("ALTER TABLE scans ADD COLUMN retry_not_before INTEGER")
        .execute(&pool)
        .await;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS scan_payloads (
            scan_id TEXT PRIMARY KEY,
            priority_words TEXT,
            domains TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )",
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS results (
            scan_id TEXT,
            domain TEXT,
            available BOOLEAN,
            expiration_date TEXT,
            signatures TEXT,
            PRIMARY KEY (scan_id, domain),
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )",
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            message TEXT,
            level TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )",
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tlds (
            suffix TEXT PRIMARY KEY,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS whois_servers (
            tld TEXT PRIMARY KEY,
            server TEXT NOT NULL,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
    )
    .execute(&pool)
    .await
    .unwrap();

    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_results_scan_id ON results(scan_id)")
        .execute(&pool)
        .await;
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_logs_scan_id ON scan_logs(scan_id)")
        .execute(&pool)
        .await;
    let _ = sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_scans_status_priority ON scans(status, priority DESC, created_at ASC)",
    )
    .execute(&pool)
    .await;
    let _ = sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_scans_retry_not_before ON scans(status, retry_not_before)",
    )
    .execute(&pool)
    .await;

    pool
}

pub async fn seed_defaults(pool: &SqlitePool) {
    let tld_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tlds")
        .fetch_one(pool)
        .await
        .unwrap_or(0);
    let whois_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM whois_servers")
        .fetch_one(pool)
        .await
        .unwrap_or(0);

    if tld_count > 0 && whois_count > 0 {
        return;
    }

    println!("Seeding default TLDs / WHOIS servers into database...");

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            eprintln!("Warning: Could not begin seed transaction: {}", e);
            return;
        }
    };

    for stmt in SEED_SQL.split(';').filter_map(|chunk| {
        let sql = chunk
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                !trimmed.is_empty() && !trimmed.starts_with("--")
            })
            .collect::<Vec<_>>()
            .join("\n");
        let sql = sql.trim().to_string();
        if sql.is_empty() { None } else { Some(sql) }
    }) {
        let seeds_tlds = stmt.starts_with("INSERT OR IGNORE INTO tlds");
        let seeds_whois = stmt.starts_with("INSERT OR IGNORE INTO whois_servers");

        if (seeds_tlds && tld_count > 0) || (seeds_whois && whois_count > 0) {
            continue;
        }

        if !seeds_tlds && !seeds_whois {
            continue;
        }

        if let Err(e) = sqlx::query(&stmt).execute(&mut *tx).await {
            let seed_type = if seeds_tlds { "TLD" } else { "WHOIS" };
            eprintln!("Warning: {} seed statement failed: {}", seed_type, e);
        }
    }

    match tx.commit().await {
        Ok(_) => println!("Database seeded successfully."),
        Err(e) => eprintln!("Warning: Seed commit failed: {}", e),
    }
}

pub async fn load_whois_servers(pool: &SqlitePool) -> HashMap<String, String> {
    sqlx::query_as::<_, (String, String)>("SELECT tld, server FROM whois_servers")
        .fetch_all(pool)
        .await
        .unwrap_or_default()
        .into_iter()
        .collect()
}

pub async fn load_tlds(pool: &SqlitePool) -> Vec<String> {
    sqlx::query_scalar::<_, String>("SELECT suffix FROM tlds ORDER BY suffix")
        .fetch_all(pool)
        .await
        .unwrap_or_default()
}
