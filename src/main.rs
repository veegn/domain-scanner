use domain_scanner::checker;
use domain_scanner::generator;
use domain_scanner::worker;

use checker::CheckerRegistry;
use clap::Parser;
use colored::*;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};

use domain_scanner::tui::TuiApp;

#[derive(Parser, Debug, Clone)]
#[command(
    author = "www.ict.run",
    version = "1.3.4",
    about = "Domain Scanner - A tool to check domain availability"
)]
struct Args {
    /// Domain length
    #[arg(short = 'l', long, default_value_t = 3)]
    length: usize,

    /// Domain suffix
    #[arg(short = 's', long, default_value = ".uk")]
    suffix: String,

    /// Domain pattern (d: numbers, D: letters, a: alphanumeric)
    #[arg(short = 'p', long, default_value = "D")]
    pattern: String,

    /// Regex filter for domain name prefix
    #[arg(short = 'r', long, default_value = "")]
    regex: String,

    /// Dictionary file path
    #[arg(long = "dict", default_value = "")]
    dict: String,

    /// Delay between queries in milliseconds
    #[arg(long, default_value_t = 1000)]
    delay: u64,

    /// Number of concurrent workers
    #[arg(long, default_value_t = 10)]
    workers: usize,

    /// Skip performance warnings
    #[arg(long)]
    force: bool,

    /// DoH server URLs
    #[arg(long)]
    doh: Vec<String>,

    /// Path to configuration file
    #[arg(long, default_value = "config.json")]
    config: String,
}

#[tokio::main]
async fn main() {
    let mut args = Args::parse();

    // Fix suffix dot
    if !args.suffix.starts_with('.') {
        args.suffix = format!(".{}", args.suffix);
    }

    // Logic checks
    if !args.dict.is_empty() {
        if args.length != 3 || args.pattern != "D" {
            println!("Note: When using dictionary mode, -l and -p parameters are ignored");
        }
    }

    // Load config
    domain_scanner::config::AppConfig::save_default_if_not_exists(&args.config);
    let mut config = domain_scanner::config::AppConfig::load_from_file(&args.config);

    // CLI args override config (DoH)
    if !args.doh.is_empty() {
        config.doh_servers = args.doh.clone();
    }

    // Create checker registry with config
    let registry = Arc::new(CheckerRegistry::with_defaults(config).await);

    // Print active checkers
    println!("Active checkers: {:?}", registry.checker_names());

    // State management
    let state_file = ".scan_state.json";
    let mut skip_count = 0;

    if let Some(state) = domain_scanner::state::ScanState::load(state_file) {
        let current_job = domain_scanner::state::ScanJobSignature {
            length: args.length,
            suffix: args.suffix.clone(),
            pattern: args.pattern.clone(),
            regex: args.regex.clone(),
            dict: args.dict.clone(),
        };

        if state.job == current_job && state.generated_count > 0 {
            println!("\n{}", "🔄 FOUND PREVIOUS SESSION".green().bold());
            println!("Last progress: {} domains checked", state.generated_count);

            let should_resume = if args.force {
                true
            } else {
                print!("Do you want to resume? [Y/n]: ");
                io::stdout().flush().unwrap_or(());
                let mut input = String::new();
                if io::stdin().read_line(&mut input).is_ok() {
                    let s = input.trim().to_lowercase();
                    s.is_empty() || s == "y" || s == "yes"
                } else {
                    false
                }
            };

            if should_resume {
                skip_count = state.generated_count;
                println!("Resuming from index {}...", skip_count);
            }
        }
    }

    // Generator
    let domain_gen = generator::generate_domains(
        args.length,
        args.suffix.clone(),
        args.pattern.clone(),
        args.regex.clone(),
        args.dict.clone(),
        skip_count,
    );

    // Spawn state saver
    let saver_generated = domain_gen.generated.clone();
    let saver_args = args.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let current = saver_generated.load(Ordering::Relaxed);
            if current > 0 {
                let mut state = domain_scanner::state::ScanState::new(
                    saver_args.length,
                    saver_args.suffix.clone(),
                    saver_args.pattern.clone(),
                    saver_args.regex.clone(),
                    saver_args.dict.clone(),
                    current,
                );
                let _ = state.save(state_file);
            }
        }
    });

    let estimated_domains = domain_gen.total_count;
    let app = Arc::new(Mutex::new(TuiApp::new(
        estimated_domains as u64,
        skip_count as u64,
    )));

    // Channels
    let (tx_results, mut rx_results) = mpsc::channel(1000);

    // Worker shared jobs receiver
    let jobs_rx = Arc::new(Mutex::new(domain_gen.domains));

    // Spawn workers
    for id in 1..=args.workers {
        let jobs = jobs_rx.clone();
        let tx = tx_results.clone();
        let delay = Duration::from_millis(args.delay);
        let registry_clone = registry.clone();

        tokio::spawn(async move {
            worker::worker(id, jobs, tx, delay, registry_clone).await;
        });
    }
    drop(tx_results);

    // Output file setup
    let suffix_clean = args.suffix.trim_start_matches('.');
    let available_file = format!(
        "available_domains_{}_{}_{}.txt",
        args.pattern, args.length, suffix_clean
    );
    let output_path = available_file.clone();

    let app_consumer = app.clone();

    // Spawn consumer task
    tokio::spawn(async move {
        // Use OpenOptions to handle file creation/append
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&output_path)
            .expect("Failed to open output file");

        while let Some(msg) = rx_results.recv().await {
            match msg {
                domain_scanner::WorkerMessage::Scanning(domain) => {
                    let mut state = app_consumer.lock().await;
                    state.scanned_count += 1; // Increment processed count
                    state.logs.push(domain_scanner::tui::LogEntry {
                        domain,
                        status: domain_scanner::tui::DomainStatus::Scanning,
                        timestamp: std::time::Instant::now(),
                        signature: None,
                    });
                }
                domain_scanner::WorkerMessage::Result(result) => {
                    // Update log status
                    {
                        let mut state = app_consumer.lock().await;
                        // Format signature string if present
                        let signature = if !result.signatures.is_empty() {
                            Some(result.signatures.join(","))
                        } else {
                            None
                        };

                        // Find matching entry - search from end as it's likely recent
                        if let Some(entry) = state
                            .logs
                            .iter_mut()
                            .rev()
                            .find(|e| e.domain == result.domain)
                        {
                            entry.status = if result.available {
                                domain_scanner::tui::DomainStatus::Available
                            } else {
                                domain_scanner::tui::DomainStatus::Registered
                            };
                            entry.timestamp = std::time::Instant::now();
                            entry.signature = signature.clone();
                        } else {
                            // If not found (race condition or whatever), append result
                            state.logs.push(domain_scanner::tui::LogEntry {
                                domain: result.domain.clone(),
                                status: if result.available {
                                    domain_scanner::tui::DomainStatus::Available
                                } else {
                                    domain_scanner::tui::DomainStatus::Registered
                                },
                                timestamp: std::time::Instant::now(),
                                signature: signature.clone(),
                            });
                        }

                        // Add to Found Domains list if available
                        if result.available {
                            state.found_domains.push(result.domain.clone());
                        }

                        if let Some(err) = &result.error {
                            state.fail_count += 1; // Increment fail count on error
                            let err_msg = if err.len() > 50 {
                                format!("{}...", &err[..47])
                            } else {
                                err.clone()
                            };
                            state.status_message =
                                format!("Error: {} ({})", err_msg, result.domain);
                        }
                    }

                    // File IO for available
                    if result.available {
                        let log_entry = format!("{}\n", result.domain);
                        let _ = file.write_all(log_entry.as_bytes());
                    }
                }
            }
        }
    });

    // Run TUI Loop
    if let Err(e) = domain_scanner::tui::run(app).await {
        eprintln!("TUI Error: {}", e);
    }

    println!("Scan finished. Results saved to {}", available_file);
}
