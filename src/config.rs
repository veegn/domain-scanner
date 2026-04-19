use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AppConfig {
    /// DoH server URLs for DNS-over-HTTPS lookups (load-balanced round-robin).
    /// Leave empty to use built-in defaults (AliDNS, DNSPod, Google, Cloudflare).
    #[serde(default)]
    pub doh_servers: Vec<String>,

    /// WHOIS server overrides (TLD -> host or host:port).
    /// Merged on top of seeded defaults; entries here take precedence.
    /// Example: {"com": "whois.my-proxy.example.com"}
    #[serde(default)]
    pub whois_servers: HashMap<String, String>,

    /// RDAP base URL overrides (suffix -> base URL).
    #[serde(default)]
    pub rdap_servers: HashMap<String, String>,

    /// RDAP bootstrap URL. Leave empty to disable RDAP or set to the IANA endpoint.
    #[serde(default)]
    pub rdap_bootstrap_url: Option<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            doh_servers: Vec::new(),
            whois_servers: HashMap::new(),
            rdap_servers: HashMap::new(),
            rdap_bootstrap_url: None,
        }
    }
}

impl AppConfig {
    pub fn load_from_file(path: &str) -> Self {
        if !Path::new(path).exists() {
            return Self::default();
        }

        match fs::read_to_string(path) {
            Ok(content) => match serde_json::from_str::<Self>(&content) {
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
            if let Ok(content) = serde_json::to_string_pretty(&Self::default()) {
                let _ = fs::write(path, content);
            }
        }
    }
}
