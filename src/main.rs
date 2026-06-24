use clap::Parser;
use domain_scanner::checker::CheckerRegistry;
use domain_scanner::config::AppConfig;
use domain_scanner::logging;
use domain_scanner::web;
use std::sync::Arc;
use tokio::sync::Semaphore;
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
    // 1. Initialize DB (creates schema if needed)
    // We do this first because the configuration is now stored in the database.
    let db = match web::init_db().await {
        Ok(db) => db,
        Err(err) => {
            eprintln!("failed to initialize database: {}", err);
            std::process::exit(1);
        }
    };

    // 2. Load runtime config from database, or migrate from file
    let config = match web::load_app_config(&db).await {
        Ok(Some(cfg)) => cfg,
        Ok(None) => {
            // Migration logic
            let fallback_cfg = if std::path::Path::new("config.json").exists() {
                let c = AppConfig::load_from_file("config.json");
                let _ = std::fs::rename("config.json", "config.json.migrated");
                c
            } else {
                AppConfig::default()
            };
            if let Err(e) = web::save_app_config(&db, &fallback_cfg).await {
                eprintln!("failed to save default config to db: {}", e);
            }
            fallback_cfg
        }
        Err(err) => {
            eprintln!("failed to load config from database: {}", err);
            std::process::exit(1);
        }
    };

    let scheduler_config = config.scheduler.clone();
    logging::init(&config.logging);

    info!(target: "domain_scanner::main", port = args.port, context = "startup", "initializing web server");

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
        max_parallel_tlds = scheduler_config.max_parallel_tlds,
        workers_per_scan = scheduler_config.workers_per_scan,
        max_global_checks = scheduler_config.max_global_checks,
        "runtime config loaded from database"
    );

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
    let streams = web::models::StreamHub::default();

    // 7. Start background task worker
    let worker_db = db.clone();
    let worker_task_control = task_control.clone();
    let worker_registry = registry.clone();
    let worker_streams = streams.clone();
    let worker_scheduler_config = scheduler_config.clone();
    let global_check_permits = Arc::new(Semaphore::new(scheduler_config.max_global_checks.max(1)));
    let worker_global_check_permits = global_check_permits.clone();
    tokio::spawn(async move {
        web::start_task_worker(
            worker_db,
            rx,
            worker_task_control,
            worker_registry,
            worker_streams,
            worker_scheduler_config,
            worker_global_check_permits,
        )
        .await;
    });

    // 8. Setup web state
    let state = Arc::new(web::AppState {
        db,
        task_tx: tx,
        task_control,
        streams,
    });

    // 9. Recover stale transient statuses and resume ready unfinished tasks.
    let recovery = web::recover_startup_tasks(&state.db).await;

    info!(
        target: "domain_scanner::main",
        context = "task_resume",
        resumable_tasks = recovery.ready_scan_ids.len(),
        recovered_running = recovery.recovered_running,
        recovered_cancelling = recovery.recovered_cancelling,
        recovered_pausing = recovery.recovered_pausing,
        repaired_counters = recovery.repaired_counters,
        "startup task scan complete"
    );

    for id in &recovery.ready_scan_ids {
        warn!(
            target: "domain_scanner::main",
            context = "task_resume",
            scan_id = %id,
            "re-queueing unfinished task"
        );
    }

    if recovery.should_wake_worker() {
        let _ = state.task_tx.try_send(());
    }

    // 10. Build router and start server
    let app = web::router(state)
        .nest_service(
            "/published",
            tower_http::services::ServeDir::new("data/published"),
        )
        .fallback_service(tower_http::services::ServeDir::new("web"));

    info!(
        target: "domain_scanner::main",
        context = "startup",
        bind = %format!("0.0.0.0:{}", args.port),
        local_url = %format!("http://localhost:{}", args.port),
        "server listening"
    );
    let listener = match tokio::net::TcpListener::bind(format!("0.0.0.0:{}", args.port)).await {
        Ok(listener) => listener,
        Err(err) => {
            error!(
                target: "domain_scanner::main",
                context = "startup",
                port = args.port,
                error = %err,
                "failed to bind web server listener"
            );
            std::process::exit(1);
        }
    };
    if let Err(err) = axum::serve(listener, app).await {
        error!(
            target: "domain_scanner::main",
            context = "shutdown",
            error = %err,
            "axum server exited with error"
        );
    }
}
