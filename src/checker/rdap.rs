//! RDAP (Registration Data Access Protocol) Checker
//!
//! This checker uses RDAP to query domain registration information.
//! RDAP is the modern replacement for WHOIS, providing structured JSON responses.

use async_trait::async_trait;
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use super::circuit_breaker::CircuitBreaker;
use super::traits::{CheckResult, CheckerPriority, DomainChecker};

/// IANA bootstrap RDAP URL (redirects to appropriate registry)
pub const RDAP_BOOTSTRAP: &str = "https://rdap.iana.org/domain/";

/// Shared HTTP client for RDAP queries with optimized settings
static RDAP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::limited(3))
        .pool_max_idle_per_host(2) // Limit connections per host to avoid overwhelming servers
        .build()
        .unwrap()
});

/// TLD-specific RDAP endpoints for better performance
/// These skip the IANA bootstrap redirect
static TLD_RDAP_MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    // Note: Some TLDs like .li have unreliable RDAP, we'll use IANA bootstrap for them
    m.insert("com", "https://rdap.verisign.com/com/v1/domain/");
    m.insert("net", "https://rdap.verisign.com/net/v1/domain/");
    m.insert(
        "org",
        "https://rdap.publicinterestregistry.net/rdap/org/domain/",
    );
    m.insert("io", "https://rdap.nic.io/domain/");
    m.insert("de", "https://rdap.denic.de/domain/");
    m.insert("uk", "https://rdap.nominet.uk/uk/domain/");
    m.insert("fr", "https://rdap.nic.fr/domain/");
    m.insert("nl", "https://rdap.sidn.nl/domain/");
    m.insert("eu", "https://rdap.eurid.eu/domain/");
    m.insert("app", "https://rdap.nic.google/domain/");
    m.insert("dev", "https://rdap.nic.google/domain/");
    m.insert("xyz", "https://rdap.nic.xyz/domain/");
    m.insert("li", "https://rdap.nic.li/rdap/domain/"); // Re-added .li
    m.insert("cn", "https://rdap.cnnic.cn/rdap/domain/"); // Re-added .cn
    m.insert("us", "https://rdap.nic.us/domain/"); // Added .us
    // .de and .dev are already present above
    m
});

/// Minimal RDAP response structure
#[derive(Deserialize, Debug)]
struct RdapResponse {
    #[serde(default)]
    status: Vec<String>,
}

/// RDAP domain checker
///
/// Queries RDAP servers to determine if a domain is registered.
/// This is the preferred method for domain availability checks.
#[derive(Debug, Clone)]
pub struct RdapChecker {
    /// Whether to use TLD-specific endpoints (faster) or always use IANA bootstrap
    pub use_tld_specific: bool,
    /// Number of retry attempts for transient errors
    pub max_retries: u32,
    /// Base delay between retries (milliseconds)
    pub retry_delay_ms: u64,
    /// Custom endpoints from configuration (highest priority)
    pub custom_endpoints: HashMap<String, String>,
    /// Circuit breaker
    pub cb: Arc<CircuitBreaker>,
}

impl RdapChecker {
    /// Create a new RDAP checker with TLD-specific endpoints enabled
    pub fn new() -> Self {
        Self {
            use_tld_specific: true,
            max_retries: 2,
            retry_delay_ms: 500,
            custom_endpoints: HashMap::new(),
            cb: Arc::new(CircuitBreaker::new(10, 60)), // 10 failures = 60s cooldown
        }
    }

    /// Create a new RDAP checker with custom settings
    pub fn with_settings(
        use_tld_specific: bool,
        max_retries: u32,
        retry_delay_ms: u64,
        custom_endpoints: HashMap<String, String>,
    ) -> Self {
        Self {
            use_tld_specific,
            max_retries,
            retry_delay_ms,
            custom_endpoints,
            cb: Arc::new(CircuitBreaker::new(10, 60)),
        }
    }

    /// Get the RDAP URL for a given TLD
    fn get_rdap_url(&self, tld: &str) -> String {
        // 1. Check custom config first
        if let Some(url) = self.custom_endpoints.get(tld) {
            return url.clone();
        }

        // 2. Check static map
        if self.use_tld_specific {
            if let Some(url) = TLD_RDAP_MAP.get(tld) {
                return (*url).to_string();
            }
        }

        // 3. Fallback to IANA
        RDAP_BOOTSTRAP.to_string()
    }

    /// Perform a single RDAP query attempt
    async fn query_once(&self, target_url: &str) -> Result<CheckResult, String> {
        let resp = RDAP_CLIENT
            .get(target_url)
            .header("Accept", "application/rdap+json")
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        let status = resp.status();

        if status.is_success() {
            // 200 OK = domain is registered
            let signatures = match resp.json::<RdapResponse>().await {
                Ok(rdap_json) => {
                    let mut sigs = vec!["RDAP".to_string()];
                    for s in rdap_json.status {
                        sigs.push(format!("RDAP:{}", s));
                    }
                    sigs
                }
                Err(_) => vec!["RDAP".to_string()],
            };
            return Ok(CheckResult::registered(signatures));
        }

        if status == reqwest::StatusCode::NOT_FOUND {
            // 404 = domain is available
            return Ok(CheckResult::available());
        }

        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err("Rate limited".to_string());
        }

        // 400, 500, etc - might be transient
        Err(format!("HTTP {}", status))
    }
}

impl Default for RdapChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DomainChecker for RdapChecker {
    fn name(&self) -> &'static str {
        "RDAP"
    }

    fn priority(&self) -> CheckerPriority {
        CheckerPriority::Standard
    }

    async fn check(&self, domain: &str) -> CheckResult {
        if !self.cb.allow_request() {
            return CheckResult::error("Circuit breaker open - RDAP skipped");
        }

        let parts: Vec<&str> = domain.split('.').collect();
        let tld = if parts.len() > 1 {
            *parts.last().unwrap()
        } else {
            return CheckResult::error("Invalid domain format");
        };

        let base_url = self.get_rdap_url(tld);
        let target_url = format!("{}{}", base_url, domain);

        // Retry loop with exponential backoff
        let mut last_error = String::new();
        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                // Exponential backoff: 500ms, 1000ms, 2000ms...
                let delay = self.retry_delay_ms * (1 << (attempt - 1));
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }

            match self.query_once(&target_url).await {
                Ok(result) => {
                    self.cb.record_success();
                    return result;
                }
                Err(e) => {
                    last_error = e.clone();

                    // Circuit breaker logic for errors
                    if e.contains("Rate limited") {
                        self.cb.record_failure();
                        break;
                    }

                    if e.contains("connection") || e.contains("timeout") {
                        self.cb.record_failure();
                    }

                    // Check if error is retryable
                    if e.contains("Rate limited") {
                        break;
                    }
                    // Connection errors, timeouts are retryable
                    if !e.contains("connection") && !e.contains("timeout") {
                        // Non-retryable error (e.g. 400 Bad Request)
                        break;
                    }
                }
            }
        }

        // If RDAP fails, we can't definitively say the domain is available or not
        // Return error so other checkers can be consulted or the domain can be retried later
        CheckResult::error(format!("RDAP: {}", last_error))
    }

    fn supports_tld(&self, tld: &str) -> bool {
        // RDAP supports most TLDs through IANA bootstrap
        // TLD-specific endpoints are just optimizations
        let _ = tld;
        true
    }

    fn is_authoritative(&self) -> bool {
        // RDAP is authoritative - if it says available, it's available
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rdap_google_com() {
        // use_tld_specific = true
        let checker = RdapChecker::new();
        let result = checker.check("google.com").await;

        // google.com is registered
        assert!(!result.available, "google.com should be available=false");
        // Should have RDAP signature
        let has_rdap = result.signatures.iter().any(|s| s.starts_with("RDAP"));
        assert!(has_rdap, "Should have RDAP signature");
    }

    #[tokio::test]
    async fn test_rdap_li_domain() {
        // Test .li domain which had issues before
        // nic.li is the registry, should exists
        let checker = RdapChecker::new();
        let result = checker.check("nic.li").await;

        if let Some(err) = result.error {
            println!(
                "Notice: RDAP check for nic.li failed with error (network issue?): {:?}",
                err
            );
            // We allow network errors in this test environment since .li might be unstable
        } else {
            assert!(
                !result.available,
                "nic.li should be registered if reachable"
            );
        }
    }

    #[tokio::test]
    async fn test_rdap_io_domain() {
        // Test .io domain which is usually reliable
        let checker = RdapChecker::new();
        let result = checker.check("nic.io").await;

        if let Some(err) = result.error {
            println!("Notice: RDAP check for nic.io failed: {:?}", err);
        } else {
            assert!(!result.available, "nic.io should be registered");
        }
    }

    #[tokio::test]
    async fn test_rdap_nonexistent() {
        let checker = RdapChecker::new();
        let domain = format!(
            "test-rdap-not-exist-{}.com",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
        let result = checker.check(&domain).await;

        // Should be available
        assert!(result.available, "random domain should be available");
    }
}

/// Get the list of TLDs with known stable RDAP endpoints
pub fn known_tlds() -> Vec<&'static str> {
    TLD_RDAP_MAP.keys().copied().collect()
}

/// Get the RDAP URL for a specific TLD (if known)
pub fn get_tld_rdap_url(tld: &str) -> Option<&'static str> {
    TLD_RDAP_MAP.get(tld).copied()
}
