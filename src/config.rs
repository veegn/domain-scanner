use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AppConfig {
    /// List of DoH servers for load balancing
    #[serde(default)]
    pub doh_servers: Vec<String>,

    /// Whois servers fallback (TLD -> Host:Port) - Future feature
    #[serde(default)]
    pub whois_servers: HashMap<String, String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            doh_servers: Vec::new(),
            whois_servers: HashMap::new(),
        }
    }
}

impl AppConfig {
    pub fn load_from_file(path: &str) -> Self {
        if !Path::new(path).exists() {
            return Self::default();
        }

        match fs::read_to_string(path) {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(config) => config,
                Err(e) => {
                    eprintln!("Warning: Failed to parse config file {}: {}", path, e);
                    Self::default()
                }
            },
            Err(e) => {
                eprintln!("Warning: Failed to read config file {}: {}", path, e);
                Self::default()
            }
        }
    }

    pub fn save_default_if_not_exists(path: &str) {
        if !Path::new(path).exists() {
            let default_config = Self::default();
            // Add some examples

            if let Ok(content) = serde_json::to_string_pretty(&default_config) {
                let _ = fs::write(path, content);
            }
        }
    }
}
