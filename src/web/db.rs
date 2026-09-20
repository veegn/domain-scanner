use anyhow::{Context, Result};
use sqlx::{
    Row,
    sqlite::{
        SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteSynchronous,
    },
};
use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;
use tracing::{info, warn};

const SEED_SQL: &str = include_str!("../../data/seed.sql");
const DNSHE_SUFFIX_SEED_SQL: &str = "INSERT OR IGNORE INTO tlds (suffix) VALUES ('l.cd'), ('us.ci'), ('bot.cd'), \
     ('de5.net'), ('ccwu.cc'), ('ddns.ge'), ('bbroot.com')";

pub async fn init_db() -> Result<SqlitePool> {
    std::fs::create_dir_all("data").context("failed to create data directory")?;
    let options = SqliteConnectOptions::from_str("sqlite:data/scans.db")
        .context("failed to build SQLite connection options")?
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(Duration::from_secs(5))
        .pragma("temp_store", "MEMORY");
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(options)
        .await
        .context("failed to open SQLite database at data/scans.db")?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS app_settings (
            id TEXT PRIMARY KEY,
            config_json TEXT NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .context("failed to create app_settings table")?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
    )
    .execute(&pool)
    .await
    .context("failed to create schema_migrations table")?;
    sqlx::query(crate::checker::dnshe::DNSHE_RATE_LIMIT_SCHEMA_SQL)
        .execute(&pool)
        .await
        .context("failed to create persistent API rate-limit table")?;

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
            scheduler_key TEXT,
            retry_not_before INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            started_at DATETIME,
            finished_at DATETIME
        )",
    )
    .execute(&pool)
    .await
    .context("failed to create scans table")?;
    add_column_if_missing(&pool, "scans", "retry_not_before", "INTEGER").await?;
    add_column_if_missing(&pool, "scans", "scheduler_key", "TEXT").await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS scan_payloads (
            scan_id TEXT PRIMARY KEY,
            priority_words TEXT,
            domains TEXT,
            dictionary_words TEXT,
            prefix TEXT,
            postfix TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )",
    )
    .execute(&pool)
    .await
    .context("failed to create scan_payloads table")?;

    add_column_if_missing(&pool, "scan_payloads", "dictionary_words", "TEXT").await?;
    add_column_if_missing(&pool, "scan_payloads", "prefix", "TEXT").await?;
    add_column_if_missing(&pool, "scan_payloads", "postfix", "TEXT").await?;
    add_column_if_missing(&pool, "scan_payloads", "dictionary_id", "TEXT").await?;
    add_column_if_missing(&pool, "scan_payloads", "dictionary_ids", "TEXT").await?;
    add_column_if_missing(&pool, "scan_payloads", "separator", "TEXT").await?;
    add_column_if_missing(&pool, "scan_payloads", "format_template", "TEXT").await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS dictionaries (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            word_count INTEGER NOT NULL DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
    )
    .execute(&pool)
    .await
    .context("failed to create dictionaries table")?;

    // `available` remains only so existing databases can keep their table
    // shape. New code never reads it and always writes false.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS results (
            scan_id TEXT,
            domain TEXT,
            available BOOLEAN,
            registration_record_absent BOOLEAN NOT NULL DEFAULT 0,
            purchasable BOOLEAN,
            expiration_date TEXT,
            signatures TEXT,
            PRIMARY KEY (scan_id, domain),
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )",
    )
    .execute(&pool)
    .await
    .context("failed to create results table")?;

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
    .context("failed to create scan_logs table")?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS scan_retries (
            scan_id TEXT NOT NULL,
            domain TEXT NOT NULL,
            attempt INTEGER NOT NULL DEFAULT 0,
            next_retry_at INTEGER NOT NULL,
            error TEXT,
            rate_limited BOOLEAN NOT NULL DEFAULT 0,
            retry_after_secs INTEGER,
            PRIMARY KEY (scan_id, domain),
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )",
    )
    .execute(&pool)
    .await
    .context("failed to create scan_retries table")?;
    add_column_if_missing(
        &pool,
        "scan_retries",
        "deferred",
        "BOOLEAN NOT NULL DEFAULT 0",
    )
    .await?;
    add_column_if_missing(&pool, "scan_retries", "resume_checker", "TEXT").await?;
    create_candidate_tables(&pool).await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tlds (
            suffix TEXT PRIMARY KEY,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
    )
    .execute(&pool)
    .await
    .context("failed to create tlds table")?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS whois_servers (
            tld TEXT PRIMARY KEY,
            server TEXT NOT NULL,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
    )
    .execute(&pool)
    .await
    .context("failed to create whois_servers table")?;

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
    .context("failed to create published_scans table")?;

    // The published legacy field is retained for the same upgrade reason.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS published_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            published_scan_id TEXT NOT NULL,
            domain TEXT NOT NULL,
            available BOOLEAN NOT NULL,
            registration_record_absent BOOLEAN NOT NULL DEFAULT 0,
            purchasable BOOLEAN,
            expiration_date TEXT,
            signatures TEXT NOT NULL DEFAULT '',
            published_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(published_scan_id) REFERENCES published_scans(id) ON DELETE CASCADE
        )",
    )
    .execute(&pool)
    .await
    .context("failed to create published_domains table")?;
    migrate_registration_status_schema(&pool).await?;
    run_data_migrations(&pool).await?;

    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_results_scan_id ON results(scan_id)")
        .execute(&pool)
        .await;
    let _ = sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_results_scan_record_absent_domain
         ON results(scan_id, registration_record_absent, domain)",
    )
    .execute(&pool)
    .await;
    let _ = sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_results_scan_record_absent
         ON results(scan_id, registration_record_absent)",
    )
    .execute(&pool)
    .await;
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_logs_scan_id ON scan_logs(scan_id)")
        .execute(&pool)
        .await;
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_logs_scan_id_id ON scan_logs(scan_id, id)")
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
    let _ = sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_scan_retries_due ON scan_retries(scan_id, next_retry_at)",
    )
    .execute(&pool)
    .await;
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_scans_suffix ON scans(suffix)")
        .execute(&pool)
        .await;
    let _ = sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_scans_scheduler_ready ON scans(status, scheduler_key, priority DESC, created_at ASC)",
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
    let _ = sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_dictionaries_updated_at ON dictionaries(updated_at DESC)",
    )
    .execute(&pool)
    .await;

    Ok(pool)
}

pub(super) async fn create_candidate_tables(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS scan_generation (
            scan_id TEXT PRIMARY KEY,
            cursor INTEGER NOT NULL DEFAULT 0,
            fingerprint TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS scan_candidates (
            scan_id TEXT NOT NULL,
            domain TEXT NOT NULL,
            position INTEGER NOT NULL,
            completed BOOLEAN NOT NULL DEFAULT 0,
            PRIMARY KEY (scan_id, domain),
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_scan_candidates_position
         ON scan_candidates(scan_id, completed, position, domain)",
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn migrate_registration_status_schema(pool: &SqlitePool) -> Result<()> {
    add_column_if_missing(
        pool,
        "results",
        "registration_record_absent",
        "BOOLEAN NOT NULL DEFAULT 0",
    )
    .await?;
    add_column_if_missing(pool, "results", "purchasable", "BOOLEAN").await?;

    add_column_if_missing(
        pool,
        "published_domains",
        "registration_record_absent",
        "BOOLEAN NOT NULL DEFAULT 0",
    )
    .await?;
    add_column_if_missing(pool, "published_domains", "purchasable", "BOOLEAN").await?;

    Ok(())
}

async fn run_data_migrations(pool: &SqlitePool) -> Result<()> {
    let applied =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM schema_migrations WHERE version = 1")
            .fetch_one(pool)
            .await
            .context("failed to inspect data migration version")?;
    if applied != 0 {
        return Ok(());
    }

    let mut tx = pool
        .begin()
        .await
        .context("failed to begin data migration")?;
    // Legacy `available` rows cannot distinguish authoritative RDAP/WHOIS
    // absence from an inconclusive DNS miss. Keep the new fields unknown and
    // repair the derived publication count exactly once.
    sqlx::query(
        "UPDATE published_scans
         SET result_count = (
             SELECT COUNT(*)
             FROM published_domains pd
             WHERE pd.published_scan_id = published_scans.id
               AND pd.registration_record_absent = 1
         )
         WHERE result_count != (
             SELECT COUNT(*)
             FROM published_domains pd
             WHERE pd.published_scan_id = published_scans.id
               AND pd.registration_record_absent = 1
         )",
    )
    .execute(&mut *tx)
    .await
    .context("failed to repair published registration-record counts")?;
    sqlx::query("INSERT INTO schema_migrations(version) VALUES (1)")
        .execute(&mut *tx)
        .await
        .context("failed to record data migration")?;
    tx.commit()
        .await
        .context("failed to commit data migration")?;
    Ok(())
}

async fn add_column_if_missing(
    pool: &SqlitePool,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<()> {
    let pragma = format!("PRAGMA table_info({table})");
    let exists: bool = sqlx::query(&pragma)
        .fetch_all(pool)
        .await
        .with_context(|| format!("failed to inspect table '{table}'"))?
        .into_iter()
        .any(|row| {
            row.try_get::<String, _>("name")
                .is_ok_and(|name| name == column)
        });

    if exists {
        return Ok(());
    }

    let sql = format!("ALTER TABLE {table} ADD COLUMN {column} {definition}");
    sqlx::query(&sql)
        .execute(pool)
        .await
        .with_context(|| format!("failed to add column '{column}' to table '{table}'"))?;
    Ok(())
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

    // This catalog addition must also run for existing installations whose
    // general seed tables are already populated.
    if let Err(e) = sqlx::query(DNSHE_SUFFIX_SEED_SQL).execute(pool).await {
        warn!(
            target: "domain_scanner::db",
            context = "seed",
            error = %e,
            "could not add DNSHE suffixes to the TLD catalog"
        );
    }

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

pub async fn load_app_config(pool: &SqlitePool) -> Result<Option<crate::config::AppConfig>> {
    let row = sqlx::query("SELECT config_json FROM app_settings WHERE id = 'singleton'")
        .fetch_optional(pool)
        .await
        .context("failed to query app_settings")?;

    if let Some(r) = row {
        let json_str: String = r.try_get("config_json")?;
        let config: crate::config::AppConfig = serde_json::from_str(&json_str)
            .context("failed to deserialize app config from database")?;
        Ok(Some(config))
    } else {
        Ok(None)
    }
}

pub async fn save_app_config(pool: &SqlitePool, config: &crate::config::AppConfig) -> Result<()> {
    let json_str = serde_json::to_string(config).context("failed to serialize app config")?;

    sqlx::query(
        "INSERT INTO app_settings (id, config_json) VALUES ('singleton', ?)
         ON CONFLICT(id) DO UPDATE SET config_json = excluded.config_json",
    )
    .bind(json_str)
    .execute(pool)
    .await
    .context("failed to save app_settings")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn seed_defaults_adds_dnshe_suffixes_to_existing_catalogs() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query("CREATE TABLE tlds (suffix TEXT PRIMARY KEY)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE whois_servers (tld TEXT PRIMARY KEY, server TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO tlds (suffix) VALUES ('com')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO whois_servers (tld, server) VALUES ('com', 'whois.example.test')")
            .execute(&pool)
            .await
            .unwrap();

        seed_defaults(&pool).await;

        let suffixes = load_tlds(&pool).await;
        for suffix in crate::checker::dnshe::DNSHE_SUPPORTED_SUFFIXES {
            assert!(suffixes.iter().any(|stored| stored == suffix));
        }
        let dnshe_whois_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM whois_servers WHERE tld IN \
             ('l.cd', 'us.ci', 'bot.cd', 'de5.net', 'ccwu.cc', 'ddns.ge', 'bbroot.com')",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(dnshe_whois_rows, 0);
    }

    #[tokio::test]
    async fn legacy_available_rows_are_not_promoted_to_stronger_claims() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query("CREATE TABLE results (domain TEXT, available BOOLEAN)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TABLE published_scans (
                id TEXT PRIMARY KEY,
                result_count INTEGER NOT NULL DEFAULT 0
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TABLE published_domains (
                published_scan_id TEXT,
                domain TEXT,
                available BOOLEAN NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO results VALUES ('legacy.test', 1)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO published_scans VALUES ('publication-1', 1)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO published_domains VALUES ('publication-1', 'legacy.test', 1)")
            .execute(&pool)
            .await
            .unwrap();

        migrate_registration_status_schema(&pool).await.unwrap();
        run_data_migrations(&pool).await.unwrap();
        run_data_migrations(&pool).await.unwrap();

        let result = sqlx::query_as::<_, (bool, Option<bool>)>(
            "SELECT registration_record_absent, purchasable FROM results",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let published = sqlx::query_as::<_, (bool, Option<bool>)>(
            "SELECT registration_record_absent, purchasable FROM published_domains",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let result_count: i64 = sqlx::query_scalar("SELECT result_count FROM published_scans")
            .fetch_one(&pool)
            .await
            .unwrap();

        assert_eq!(result, (false, None));
        assert_eq!(published, (false, None));
        assert_eq!(result_count, 0);
        let migrations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM schema_migrations")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(migrations, 1);
    }
}
