use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

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

#[derive(Serialize)]
pub struct ScanStatus {
    pub id: String,
    pub status: String,
    pub total: i64,
    pub processed: i64,
    pub found: i64,
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
