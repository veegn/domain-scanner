use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::warn;

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

    /// Logging configuration.
    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LoggingConfig {
    /// Whether to keep logging to stdout/stderr.
    #[serde(default = "default_true")]
    pub console_enabled: bool,

    /// Whether to persist logs to files.
    #[serde(default = "default_true")]
    pub file_enabled: bool,

    /// Directory where log files are written.
    #[serde(default = "default_log_dir")]
    pub directory: PathBuf,

    /// File name prefix, final file name is prefix-YYYY-MM-DD.log.
    #[serde(default = "default_log_prefix")]
    pub file_prefix: String,

    /// Number of log files to keep. Older files are deleted on startup.
    #[serde(default = "default_log_retention")]
    pub max_files: usize,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            doh_servers: Vec::new(),
            whois_servers: HashMap::new(),
            rdap_servers: HashMap::new(),
            rdap_bootstrap_url: None,
            logging: LoggingConfig::default(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            console_enabled: true,
            file_enabled: true,
            directory: default_log_dir(),
            file_prefix: default_log_prefix(),
            max_files: default_log_retention(),
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
                    warn!(
                        target: "domain_scanner::config",
                        context = "config_load",
                        path,
                        error = %e,
                        "failed to parse config file, using defaults"
                    );
                    Self::default()
                }
            },
            Err(e) => {
                warn!(
                    target: "domain_scanner::config",
                    context = "config_load",
                    path,
                    error = %e,
                    "failed to read config file, using defaults"
                );
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

fn default_true() -> bool {
    true
}

fn default_log_dir() -> PathBuf {
    PathBuf::from("logs")
}

fn default_log_prefix() -> String {
    "domain-scanner".to_string()
}

fn default_log_retention() -> usize {
    14
}
