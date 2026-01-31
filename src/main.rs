use domain_scanner::checker;
use domain_scanner::generator;
// reserved is internal to checker mostly but used in main? No, used in generator?
// reserved is used in check?
// Let's check main.rs usages.
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
    #[arg(short = 's', long, default_value = ".li")]
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

    /// Show registered domains in output
    #[arg(long)]
    show_registered: bool,

    /// Skip performance warnings
    #[arg(long)]
    force: bool,

    /// DoH server URL
    #[arg(long, default_value = "https://dns.alidns.com/resolve")]
    doh: String,

    /// Path to configuration file
    #[arg(long, default_value = "config.json")]
    config: String,
}

fn show_motd() {
    println!(
        "{}",
        "\
╔════════════════════════════════════════════════════════════╗
║                    Domain Scanner v1.3.4                   ║
║                                                            ║
║  A powerful tool for checking domain name availability     ║
║                                                            ║
║  Developer: www.ict.run                                    ║
║  GitHub:    https://github.com/xuemian168/domain-scanner   ║
║                                                            ║
║  License:   AGPL-3.0                                       ║
║  Copyright © 2025                                          ║
╚════════════════════════════════════════════════════════════╝\
"
        .cyan()
    );
    println!();
}

fn show_performance_warning(length: usize, pattern: &str, delay: u64, workers: usize) -> bool {
    let charset_size: u64 = match pattern {
        "d" => 10,
        "D" => 26,
        "a" => 36,
        _ => 26,
    };

    let total_domains = charset_size.pow(length as u32);
    let estimated_seconds = (total_domains * delay) / (workers as u64 * 1000);
    let estimated_hours = estimated_seconds as f64 / 3600.0;
    let estimated_days = estimated_hours / 24.0;

    println!("\n{}", "⚠️  PERFORMANCE WARNING ⚠️".yellow().bold());
    println!("═══════════════════════════════════════════════════════");
    println!(
        "You are about to scan {} domains with the following settings:",
        total_domains.to_string().red().bold()
    );
    println!("• Pattern: {} (charset size: {})", pattern, charset_size);
    println!("• Length: {} characters", length);
    println!("• Workers: {}", workers);
    println!("• Delay: {} ms between queries", delay);
    println!();

    println!("📊 {}", "Estimated Impact:".cyan().bold());
    if estimated_days >= 1.0 {
        println!(
            "• Scan time: ~{:.1} days ({:.1} hours)",
            estimated_days, estimated_hours
        );
    } else if estimated_hours >= 1.0 {
        println!(
            "• Scan time: ~{:.1} hours ({:.0} minutes)",
            estimated_hours,
            estimated_hours * 60.0
        );
    } else {
        println!(
            "• Scan time: ~{:.0} minutes",
            estimated_seconds as f64 / 60.0
        );
    }
    println!("• Network requests: {} total", total_domains);
    println!();

    print!("\nDo you want to continue? (y/N): ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    let input = input.trim().to_lowercase();
    input == "y" || input == "yes"
}

#[tokio::main]
async fn main() {
    show_motd();
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
    } else {
        // Warning
        if args.length > 5 && !args.force {
            if !show_performance_warning(args.length, &args.pattern, args.delay, args.workers) {
                println!("Scan cancelled by user.");
                std::process::exit(0);
            }
            println!();
        }
    }

    // Load config
    domain_scanner::config::AppConfig::save_default_if_not_exists(&args.config);
    let mut config = domain_scanner::config::AppConfig::load_from_file(&args.config);

    // CLI args override config (DoH)
    // Note: Since 'doh' has a default value in CLI, it will always be some string.
    // Ideally we would check if user passed it explicitly, but for now CLI takes precedence.
    config.doh_url = Some(args.doh.clone());

    // Create checker registry with config
    let registry = Arc::new(CheckerRegistry::with_defaults(config));

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

        while let Some(result) = rx_results.recv().await {
            if result.available {
                let log_entry = format!("{}\n", result.domain);

                // Ignore write errors to keep scanning
                let _ = file.write_all(log_entry.as_bytes());

                let mut state = app_consumer.lock().await;
                state.found_domains.push(result.domain);
            } else if let Some(err) = result.error {
                let mut state = app_consumer.lock().await;
                let err_msg = if err.len() > 50 {
                    format!("{}...", &err[..47])
                } else {
                    err
                };
                state.status_message = format!("Error: {} ({})", err_msg, result.domain);
            }
        }
    });

    // Run TUI Loop
    let stats_generated = domain_gen.generated.clone();
    if let Err(e) = domain_scanner::tui::run(app, stats_generated).await {
        eprintln!("TUI Error: {}", e);
    }

    println!("Scan finished. Results saved to {}", available_file);
}
