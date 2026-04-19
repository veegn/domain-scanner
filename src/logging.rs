use crate::config::LoggingConfig;
use chrono::Local;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use time::UtcOffset;
use time::format_description::well_known::Rfc3339;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::fmt::time::OffsetTime;
use tracing_subscriber::layer::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

static FILE_GUARD: OnceLock<Mutex<Option<WorkerGuard>>> = OnceLock::new();

pub fn init(config: &LoggingConfig) {
    let timer = OffsetTime::new(
        UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC),
        Rfc3339,
    );

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("info,hyper=warn,h2=warn,reqwest=warn,rustls=warn,sqlx=warn,tower_http=warn")
    });

    let console_layer = if config.console_enabled {
        Some(
            fmt::layer()
                .with_timer(timer.clone())
                .with_target(true)
                .with_level(true)
                .with_thread_ids(false)
                .with_thread_names(false)
                .compact()
                .boxed(),
        )
    } else {
        None
    };

    let mut file_layer = None;
    if config.file_enabled {
        if let Some((writer, guard)) = build_file_writer(config) {
            file_layer = Some(
                fmt::layer()
                    .with_ansi(false)
                    .with_timer(timer)
                    .with_target(true)
                    .with_level(true)
                    .with_thread_ids(false)
                    .with_thread_names(false)
                    .compact()
                    .with_writer(writer)
                    .boxed(),
            );

            let guard_slot = FILE_GUARD.get_or_init(|| Mutex::new(None));
            if let Ok(mut slot) = guard_slot.lock() {
                *slot = Some(guard);
            }
        }
    }

    tracing_subscriber::registry()
        .with(filter)
        .with(console_layer)
        .with(file_layer)
        .init();
}

fn build_file_writer(
    config: &LoggingConfig,
) -> Option<(
    tracing_appender::non_blocking::NonBlocking,
    tracing_appender::non_blocking::WorkerGuard,
)> {
    if let Err(err) = fs::create_dir_all(&config.directory) {
        eprintln!(
            "failed to create log directory {}: {}",
            config.directory.display(),
            err
        );
        return None;
    }

    cleanup_old_logs(
        &config.directory,
        &config.file_prefix,
        config.max_files.max(1),
    );

    let file_path = daily_log_path(&config.directory, &config.file_prefix);
    let file_appender = tracing_appender::rolling::never(
        file_path.parent().unwrap_or_else(|| Path::new(".")),
        file_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("domain-scanner.log"),
    );
    let (writer, guard) = tracing_appender::non_blocking(file_appender);
    Some((writer, guard))
}

fn daily_log_path(directory: &Path, prefix: &str) -> PathBuf {
    let date = Local::now().format("%Y-%m-%d").to_string();
    directory.join(format!("{}-{}.log", prefix, date))
}

fn cleanup_old_logs(directory: &Path, prefix: &str, keep: usize) {
    let read_dir = match fs::read_dir(directory) {
        Ok(read_dir) => read_dir,
        Err(err) => {
            eprintln!(
                "failed to read log directory {}: {}",
                directory.display(),
                err
            );
            return;
        }
    };

    let mut log_files: Vec<(PathBuf, std::time::SystemTime)> = read_dir
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path();
            let name = path.file_name()?.to_str()?;
            if !name.starts_with(prefix) || !name.ends_with(".log") {
                return None;
            }
            let modified = entry
                .metadata()
                .ok()
                .and_then(|meta| meta.modified().ok())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            Some((path, modified))
        })
        .collect();

    if log_files.len() <= keep {
        return;
    }

    log_files.sort_by_key(|(_, modified)| *modified);
    let remove_count = log_files.len().saturating_sub(keep);

    for (path, _) in log_files.into_iter().take(remove_count) {
        if let Err(err) = fs::remove_file(&path) {
            eprintln!("failed to remove old log file {}: {}", path.display(), err);
        }
    }
}
