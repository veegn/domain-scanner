use crate::config::LoggingConfig;
use std::fs;
use std::sync::{Mutex, OnceLock};
use time::UtcOffset;
use time::format_description::well_known::Rfc3339;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
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
    if config.file_enabled
        && let Some((writer, guard)) = build_file_writer(config)
    {
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

    let file_appender = match RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix(&config.file_prefix)
        .filename_suffix("log")
        .max_log_files(config.max_files.max(1))
        .build(&config.directory)
    {
        Ok(appender) => appender,
        Err(err) => {
            eprintln!(
                "failed to initialize rolling log appender in {}: {}",
                config.directory.display(),
                err
            );
            return None;
        }
    };
    let (writer, guard) = tracing_appender::non_blocking(file_appender);
    Some((writer, guard))
}
