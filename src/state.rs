use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct ScanJobSignature {
    pub length: usize,
    pub suffix: String,
    pub pattern: String,
    pub regex: String,
    pub dict: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ScanState {
    pub job: ScanJobSignature,
    pub generated_count: i64,
    pub timestamp: u64,
}

impl ScanState {
    pub fn new(
        length: usize,
        suffix: String,
        pattern: String,
        regex: String,
        dict: String,
        generated_count: i64,
    ) -> Self {
        Self {
            job: ScanJobSignature {
                length,
                suffix,
                pattern,
                regex,
                dict,
            },
            generated_count,
            timestamp: Self::current_timestamp(),
        }
    }

    pub fn load(path: &str) -> Option<Self> {
        if !Path::new(path).exists() {
            return None;
        }

        match fs::read_to_string(path) {
            Ok(content) => serde_json::from_str(&content).ok(),
            Err(_) => None,
        }
    }

    pub fn save(&mut self, path: &str) -> std::io::Result<()> {
        self.timestamp = Self::current_timestamp();
        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}
