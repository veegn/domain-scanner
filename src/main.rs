use clap::Parser;
use domain_scanner::checker::CheckerRegistry;
use domain_scanner::config::AppConfig;
use domain_scanner::web;
use sqlx::Row;
use std::sync::Arc;
use tokio::sync::mpsc;

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

    println!("Initializing Domain Scanner Web Server...");
    println!("Loading runtime config from config.json");

    // 1. Load runtime config (DoH servers, RDAP URL, WHOIS overrides)
    AppConfig::save_default_if_not_exists("config.json");
    let config = AppConfig::load_from_file("config.json");
    println!(
        "Runtime config loaded: {} DoH overrides, {} WHOIS overrides, {} RDAP overrides, bootstrap={}",
        config.doh_servers.len(),
        config.whois_servers.len(),
        config.rdap_servers.len(),
        config
            .rdap_bootstrap_url
            .as_deref()
            .filter(|v| !v.is_empty())
            .unwrap_or("disabled")
    );

    // 2. Initialize DB (creates schema if needed)
    println!("Initializing database schema");
    let db = web::init_db().await;

    // 3. Seed default TLDs + WHOIS servers on first startup
    println!("Seeding default catalog data when required");
    web::seed_defaults(&db).await;

    // 4. Load WHOIS servers from DB, then merge config.json overrides (config wins)
    let mut whois_servers = web::load_whois_servers(&db).await;
    println!(
        "Loaded {} WHOIS server mappings from database defaults",
        whois_servers.len()
    );
    for (tld, server) in &config.whois_servers {
        whois_servers.insert(tld.clone(), server.clone());
    }
    println!(
        "WHOIS server mapping ready after config merge: {} entries",
        whois_servers.len()
    );

    // 5. Build checker registry
    println!("Building checker registry");
    let registry = Arc::new(CheckerRegistry::with_defaults(config, whois_servers).await);
    println!("Checker registry ready");

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

    println!("Found {} resumable tasks on startup", pending_tasks.len());

    for task in pending_tasks {
        if let Ok(id) = task.try_get::<String, _>("id") {
            println!("Re-queueing unfinished task: {}", id);
            let _ = state.task_tx.try_send(());
        }
    }

    // 10. Build router and start server
    let app = web::router(state).fallback_service(tower_http::services::ServeDir::new("web"));

    println!("Server running on http://localhost:{}", args.port);
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", args.port))
        .await
        .unwrap();
    if let Err(err) = axum::serve(listener, app).await {
        eprintln!("Fatal: axum server exited with error: {}", err);
    }
}
