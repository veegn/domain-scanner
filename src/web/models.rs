use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{Mutex as AsyncMutex, broadcast, mpsc};

const MAX_GENERATED_LENGTH: usize = 8;
const MAX_GENERATED_CANDIDATES: u128 = 2_000_000;
const MAX_REGEX_LENGTH: usize = 256;
const MAX_PRIORITY_WORDS: usize = 5_000;
const MAX_PRIORITY_WORD_LENGTH: usize = 63;
const MAX_DOMAINS_PER_SCAN: usize = 50_000;
const MAX_DOMAIN_LENGTH: usize = 253;
const MAX_SUFFIX_LENGTH: usize = 32;

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub task_tx: mpsc::Sender<()>, // Wake up signal
    pub task_control: TaskControl,
    pub streams: StreamHub,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct StartScanRequest {
    pub length: usize,
    pub suffix: String,
    pub pattern: String,
    pub regex: Option<String>,
    pub priority_words: Option<Vec<String>>,
    pub domains: Option<Vec<String>>,
}

#[derive(Clone, Default)]
pub struct TaskControl {
    flags: Arc<Mutex<HashMap<String, Arc<AtomicU8>>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskSignal {
    Run = 0,
    Cancel = 1,
    Pause = 2,
}

impl TaskControl {
    pub fn register(&self, scan_id: &str) -> Arc<AtomicU8> {
        let flag = Arc::new(AtomicU8::new(TaskSignal::Run as u8));
        let mut flags = self.flags.lock().expect("task control mutex poisoned");
        flags.insert(scan_id.to_string(), flag.clone());
        flag
    }

    pub fn cancel(&self, scan_id: &str) -> bool {
        let flags = self.flags.lock().expect("task control mutex poisoned");
        if let Some(flag) = flags.get(scan_id) {
            flag.store(TaskSignal::Cancel as u8, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    pub fn pause(&self, scan_id: &str) -> bool {
        let flags = self.flags.lock().expect("task control mutex poisoned");
        if let Some(flag) = flags.get(scan_id) {
            let _ = flag.compare_exchange(
                TaskSignal::Run as u8,
                TaskSignal::Pause as u8,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
            true
        } else {
            false
        }
    }

    pub fn signal(flag: &AtomicU8) -> TaskSignal {
        match flag.load(Ordering::Relaxed) {
            1 => TaskSignal::Cancel,
            2 => TaskSignal::Pause,
            _ => TaskSignal::Run,
        }
    }

    pub fn unregister(&self, scan_id: &str) {
        let mut flags = self.flags.lock().expect("task control mutex poisoned");
        flags.remove(scan_id);
    }
}

impl StartScanRequest {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(regex) = &self.regex {
            if regex.len() > MAX_REGEX_LENGTH {
                return Err(format!(
                    "Regex is too long (max {} chars)",
                    MAX_REGEX_LENGTH
                ));
            }

            regex::Regex::new(regex).map_err(|e| format!("Invalid regex: {}", e))?;
        }

        if let Some(domains) = &self.domains {
            if domains.is_empty() {
                return Err("Domains list cannot be empty".to_string());
            }

            if domains.len() > MAX_DOMAINS_PER_SCAN {
                return Err(format!(
                    "Too many domains in one scan (max {})",
                    MAX_DOMAINS_PER_SCAN
                ));
            }

            for domain in domains {
                validate_domain(domain)?;
            }

            return Ok(());
        }

        if self.length == 0 || self.length > MAX_GENERATED_LENGTH {
            return Err(format!(
                "Generated scan length must be between 1 and {}",
                MAX_GENERATED_LENGTH
            ));
        }

        if !matches!(self.pattern.as_str(), "d" | "D" | "a") {
            return Err("Pattern must be one of: d, D, a".to_string());
        }

        validate_suffix(&self.suffix)?;

        if let Some(priority_words) = &self.priority_words {
            if priority_words.len() > MAX_PRIORITY_WORDS {
                return Err(format!(
                    "Too many priority words (max {})",
                    MAX_PRIORITY_WORDS
                ));
            }

            for word in priority_words {
                validate_priority_word(word)?;
            }
        }

        let charset_size = match self.pattern.as_str() {
            "d" => 10u128,
            "D" => 26u128,
            "a" => 36u128,
            _ => unreachable!(),
        };

        let estimated = charset_size
            .checked_pow(self.length as u32)
            .ok_or_else(|| "Requested scan space is too large".to_string())?;

        if estimated > MAX_GENERATED_CANDIDATES {
            return Err(format!(
                "Requested scan space is too large (max {} candidates before filtering)",
                MAX_GENERATED_CANDIDATES
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanStatus {
    pub id: String,
    pub status: String,
    pub total: i64,
    pub processed: i64,
    pub found: i64,
    /// Number of domains currently deferred for batch replay retry.
    /// Only non-zero while a scan is running and has retryable failures.
    #[serde(skip_serializing_if = "is_zero")]
    pub deferred: i64,
}

fn is_zero(v: &i64) -> bool {
    *v == 0
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct ScanSummary {
    pub id: String,
    pub status: String,
    pub length: i64,
    pub suffix: String,
    pub pattern: String,
    pub regex: Option<String>,
    pub has_domains: bool,
    pub total: i64,
    pub processed: i64,
    pub found: i64,
    pub finished_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct ScanLogEvent {
    pub id: i64,
    pub message: String,
    pub level: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct ScanResultEvent {
    pub event_id: i64,
    pub domain: String,
    pub available: bool,
    pub expiration_date: Option<String>,
    pub signatures: String,
}

#[derive(Debug, Clone)]
pub enum ScanStreamMessage {
    Status(ScanStatus),
    Log(ScanLogEvent),
    Result(ScanResultEvent),
    Deleted(String),
    Complete(String),
}

#[derive(Clone)]
pub struct StreamHub {
    scans_tx: broadcast::Sender<u64>,
    scans_version: Arc<AtomicU64>,
    scan_channels: Arc<AsyncMutex<HashMap<String, broadcast::Sender<ScanStreamMessage>>>>,
}

impl Default for StreamHub {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamHub {
    pub fn new() -> Self {
        let (scans_tx, _) = broadcast::channel(128);
        Self {
            scans_tx,
            scans_version: Arc::new(AtomicU64::new(0)),
            scan_channels: Arc::new(AsyncMutex::new(HashMap::new())),
        }
    }

    pub fn notify_scans(&self) -> u64 {
        let version = self.scans_version.fetch_add(1, Ordering::Relaxed) + 1;
        let _ = self.scans_tx.send(version);
        version
    }

    pub fn current_scans_version(&self) -> u64 {
        self.scans_version.load(Ordering::Relaxed)
    }

    pub fn subscribe_scans(&self) -> broadcast::Receiver<u64> {
        self.scans_tx.subscribe()
    }

    pub async fn subscribe_scan(&self, scan_id: &str) -> broadcast::Receiver<ScanStreamMessage> {
        self.scan_sender(scan_id).await.subscribe()
    }

    pub async fn publish_scan(&self, scan_id: &str, message: ScanStreamMessage) {
        let sender = self.scan_sender(scan_id).await;
        let _ = sender.send(message);
    }

    async fn scan_sender(&self, scan_id: &str) -> broadcast::Sender<ScanStreamMessage> {
        let mut channels = self.scan_channels.lock().await;
        channels
            .entry(scan_id.to_string())
            .or_insert_with(|| {
                let (tx, _) = broadcast::channel(512);
                tx
            })
            .clone()
    }

    /// Remove the broadcast channel for a scan after it completes or is deleted.
    /// Must be called after the final `Complete` or `Deleted` message is published
    /// so that all live subscribers receive that message before the entry is dropped.
    pub async fn cleanup_scan(&self, scan_id: &str) {
        let mut channels = self.scan_channels.lock().await;
        channels.remove(scan_id);
    }
}

#[derive(Deserialize)]
pub struct ReorderRequest {
    pub direction: String,
}

fn validate_domain(domain: &str) -> Result<(), String> {
    let domain = domain.trim();
    if domain.is_empty() {
        return Err("Domain cannot be empty".to_string());
    }

    if domain.len() > MAX_DOMAIN_LENGTH {
        return Err(format!(
            "Domain '{}' exceeds max length {}",
            domain, MAX_DOMAIN_LENGTH
        ));
    }

    let lower = domain.to_ascii_lowercase();
    let parts: Vec<&str> = lower.split('.').collect();
    if parts.len() < 2 {
        return Err(format!("Domain '{}' must include a TLD", domain));
    }

    for label in parts {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("Domain '{}' has an invalid label", domain));
        }

        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!("Domain '{}' has an invalid label", domain));
        }

        if !label
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(format!("Domain '{}' contains invalid characters", domain));
        }
    }

    Ok(())
}

fn validate_suffix(suffix: &str) -> Result<(), String> {
    if suffix.is_empty() || suffix.len() > MAX_SUFFIX_LENGTH {
        return Err(format!(
            "Suffix must be between 1 and {} characters",
            MAX_SUFFIX_LENGTH
        ));
    }

    if !suffix.starts_with('.') {
        return Err("Suffix must start with '.'".to_string());
    }

    validate_domain(&format!("example{}", suffix))
}

fn validate_priority_word(word: &str) -> Result<(), String> {
    let word = word.trim();
    if word.is_empty() {
        return Ok(());
    }

    if word.len() > MAX_PRIORITY_WORD_LENGTH {
        return Err(format!(
            "Priority word '{}' exceeds max length {}",
            word, MAX_PRIORITY_WORD_LENGTH
        ));
    }

    if !word
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(format!(
            "Priority word '{}' contains invalid characters",
            word
        ));
    }

    Ok(())
}
