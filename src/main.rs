use clap::Parser;
use domain_scanner::checker::CheckerRegistry;
use domain_scanner::config::AppConfig;
use domain_scanner::logging;
use domain_scanner::web;
use sqlx::Row;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "Domain Scanner - Web Service Mode")]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value_t = 3000)]
    port: u16,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    AppConfig::save_default_if_not_exists("config.json");
    let config = AppConfig::load_from_file("config.json");
    logging::init(&config.logging);

    info!(target: "domain_scanner::main", port = args.port, context = "startup", "initializing web server");

    // 1. Load runtime config (DoH servers, RDAP URL, WHOIS overrides)
    info!(
        target: "domain_scanner::main",
        context = "config",
        doh_overrides = config.doh_servers.len(),
        whois_overrides = config.whois_servers.len(),
        rdap_overrides = config.rdap_servers.len(),
        rdap_bootstrap = config
            .rdap_bootstrap_url
            .as_deref()
            .filter(|v| !v.is_empty())
            .unwrap_or("disabled"),
        log_directory = %config.logging.directory.display(),
        log_file_prefix = %config.logging.file_prefix,
        log_max_files = config.logging.max_files,
        "runtime config loaded"
    );

    // 2. Initialize DB (creates schema if needed)
    let db = web::init_db().await;

    // 3. Seed default TLDs + WHOIS servers on first startup
    web::seed_defaults(&db).await;

    // 4. Load WHOIS servers from DB, then merge config.json overrides (config wins)
    let mut whois_servers = web::load_whois_servers(&db).await;
    info!(
        target: "domain_scanner::main",
        context = "whois",
        db_entries = whois_servers.len(),
        "loaded whois mappings from database"
    );
    for (tld, server) in &config.whois_servers {
        whois_servers.insert(tld.clone(), server.clone());
    }
    info!(
        target: "domain_scanner::main",
        context = "whois",
        merged_entries = whois_servers.len(),
        "whois mapping merge complete"
    );

    // 5. Build checker registry
    let registry = Arc::new(CheckerRegistry::with_defaults(config, whois_servers).await);
    info!(
        target: "domain_scanner::main",
        context = "checker_registry",
        "checker registry ready"
    );

    // 6. Setup Task Queue (single background worker)
    let (tx, rx) = mpsc::channel::<()>(100);
    let task_control = web::models::TaskControl::default();

    // 7. Start background task worker
    let worker_db = db.clone();
    let worker_task_control = task_control.clone();
    let worker_registry = registry.clone();
    tokio::spawn(async move {
        web::start_task_worker(worker_db, rx, worker_task_control, worker_registry).await;
    });

    // 8. Setup web state
    let state = Arc::new(web::AppState {
        db,
        task_tx: tx,
        task_control,
    });

    // 9. Resume unfinished tasks from previous run
    let pending_tasks = sqlx::query(
        "SELECT id FROM scans
         WHERE status IN ('pending', 'running')
           AND (retry_not_before IS NULL OR retry_not_before <= strftime('%s','now'))
         ORDER BY created_at ASC",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    info!(
        target: "domain_scanner::main",
        context = "task_resume",
        resumable_tasks = pending_tasks.len(),
        "startup task scan complete"
    );

    for task in pending_tasks {
        if let Ok(id) = task.try_get::<String, _>("id") {
            warn!(
                target: "domain_scanner::main",
                context = "task_resume",
                scan_id = %id,
                "re-queueing unfinished task"
            );
            let _ = state.task_tx.try_send(());
        }
    }

    // 10. Build router and start server
    let app = web::router(state).fallback_service(tower_http::services::ServeDir::new("web"));

    info!(
        target: "domain_scanner::main",
        context = "startup",
        bind = %format!("0.0.0.0:{}", args.port),
        local_url = %format!("http://localhost:{}", args.port),
        "server listening"
    );
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", args.port))
        .await
        .unwrap();
    if let Err(err) = axum::serve(listener, app).await {
        error!(
            target: "domain_scanner::main",
            context = "shutdown",
            error = %err,
            "axum server exited with error"
        );
    }
}
