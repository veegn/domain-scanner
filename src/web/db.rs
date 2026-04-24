use sqlx::sqlite::SqlitePool;
use std::collections::HashMap;
use tracing::{info, warn};

const SEED_SQL: &str = include_str!("../../data/seed.sql");

pub async fn init_db() -> SqlitePool {
    let _ = std::fs::create_dir_all("data");
    let pool = SqlitePool::connect("sqlite:data/scans.db?mode=rwc")
        .await
        .unwrap();

    let pragmas = [
        "PRAGMA foreign_keys = ON;",
        "PRAGMA journal_mode = WAL;",
        "PRAGMA synchronous = NORMAL;",
        "PRAGMA busy_timeout = 5000;",
        "PRAGMA temp_store = MEMORY;",
    ];
    for pragma in pragmas {
        let _ = sqlx::query(pragma).execute(&pool).await;
    }

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

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS published_scans (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            slug TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            description TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            static_dir TEXT NOT NULL,
            result_count INTEGER NOT NULL DEFAULT 0,
            published_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )",
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS published_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            published_scan_id TEXT NOT NULL,
            domain TEXT NOT NULL,
            available BOOLEAN NOT NULL,
            expiration_date TEXT,
            signatures TEXT NOT NULL DEFAULT '',
            published_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(published_scan_id) REFERENCES published_scans(id) ON DELETE CASCADE
        )",
    )
    .execute(&pool)
    .await
    .unwrap();

    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_results_scan_id ON results(scan_id)")
        .execute(&pool)
        .await;
    let _ = sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_results_scan_available_domain ON results(scan_id, available, domain)",
    )
    .execute(&pool)
    .await;
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_logs_scan_id ON scan_logs(scan_id)")
        .execute(&pool)
        .await;
    let _ = sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_logs_scan_id_id ON scan_logs(scan_id, id)",
    )
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
    let _ =
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_published_scans_published_at ON published_scans(published_at DESC)")
            .execute(&pool)
            .await;
    let _ = sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_published_scans_status_published_at ON published_scans(status, published_at DESC, updated_at DESC)",
    )
    .execute(&pool)
    .await;
    let _ = sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_published_domains_domain ON published_domains(domain)",
    )
    .execute(&pool)
    .await;
    let _ = sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_published_domains_domain_nocase ON published_domains(domain COLLATE NOCASE)",
    )
    .execute(&pool)
    .await;
    let _ = sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_published_domains_scan_domain ON published_domains(published_scan_id, domain)",
    )
    .execute(&pool)
    .await;
    let _ = sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_published_domains_published_at ON published_domains(published_at DESC)",
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

    info!(
        target: "domain_scanner::db",
        context = "seed",
        tld_seed_needed = tld_count == 0,
        whois_seed_needed = whois_count == 0,
        "seeding default catalog data"
    );

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            warn!(
                target: "domain_scanner::db",
                context = "seed",
                error = %e,
                "could not begin seed transaction"
            );
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
            warn!(
                target: "domain_scanner::db",
                context = "seed",
                seed_type,
                error = %e,
                "seed statement failed"
            );
        }
    }

    match tx.commit().await {
        Ok(_) => info!(
            target: "domain_scanner::db",
            context = "seed",
            "database seed completed"
        ),
        Err(e) => warn!(
            target: "domain_scanner::db",
            context = "seed",
            error = %e,
            "seed commit failed"
        ),
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
