//! DNS over HTTPS (DoH) Checker
//!
//! This checker uses DNS over HTTPS to quickly determine if a domain has DNS records.
//! If a domain has NS records, it's very likely registered.

use async_trait::async_trait;
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;

use super::circuit_breaker::CircuitBreaker;
use super::traits::{CheckResult, CheckerPriority, DomainChecker};

/// Default DoH server URL
pub const DEFAULT_DOH_URL: &str = "https://dns.alidns.com/resolve";

/// Shared HTTP client for DoH queries
static DOH_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
});

#[derive(Deserialize, Debug)]
struct DohAnswer {
    // Fields are parsed but not used directly
}

#[derive(Deserialize, Debug)]
struct DohResponse {
    #[serde(rename = "Answer")]
    answer: Option<Vec<DohAnswer>>,
}

/// DNS over HTTPS checker
///
/// Queries a DoH server to check if a domain has DNS records.
/// This is typically the fastest network-based check.
#[derive(Debug, Clone)]
pub struct DohChecker {
    /// The DoH server URL to use
    pub doh_url: String,
    /// Circuit breaker to prevent cascading failures
    pub cb: Arc<CircuitBreaker>,
}

impl DohChecker {
    /// Create a new DoH checker with the default server
    pub fn new() -> Self {
        Self::with_url(DEFAULT_DOH_URL)
    }

    /// Create a new DoH checker with a custom server URL
    pub fn with_url(url: impl Into<String>) -> Self {
        Self {
            doh_url: url.into(),
            cb: Arc::new(CircuitBreaker::new(20, 30)), // 20 failures = 30s cooldown
        }
    }
}

impl Default for DohChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DomainChecker for DohChecker {
    fn name(&self) -> &'static str {
        "DoH"
    }

    fn priority(&self) -> CheckerPriority {
        CheckerPriority::Fast
    }

    async fn check(&self, domain: &str) -> CheckResult {
        if !self.cb.allow_request() {
            // Circuit is open, skip DoH check
            return CheckResult::available();
        }

        let url = format!("{}?name={}.&type=NS", self.doh_url, domain);

        let resp = match DOH_CLIENT
            .get(&url)
            .header("Accept", "application/dns-json")
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                self.cb.record_failure();
                return CheckResult::error(format!("DoH request failed: {}", e));
            }
        };

        if !resp.status().is_success() {
            self.cb.record_failure();
            // If DoH fails, we can't determine status - don't treat as error
            return CheckResult::available(); // Assume available, let other checkers confirm
        }

        self.cb.record_success();

        let result: DohResponse = match resp.json().await {
            Ok(r) => r,
            Err(_) => return CheckResult::available(),
        };

        if let Some(answers) = result.answer {
            if !answers.is_empty() {
                return CheckResult::registered(vec!["DNS".to_string()]);
            }
        }

        CheckResult::available()
    }

    fn supports_tld(&self, _tld: &str) -> bool {
        // DoH can check any TLD
        true
    }

    fn is_authoritative(&self) -> bool {
        // DNS presence is a strong indicator but not 100% authoritative
        // (domain could be registered without NS records)
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_doh_google_com() {
        let checker = DohChecker::new();
        // google.com has NS records
        let result = checker.check("google.com").await;
        // Should be registered (DNS signature)
        assert!(!result.available);
        assert!(result.signatures.contains(&"DNS".to_string()));
    }

    #[tokio::test]
    async fn test_doh_nonexistent() {
        let checker = DohChecker::new();
        // Use a random domain that definitely doesn't exist
        let domain = format!(
            "test-domain-not-exist-{}.com",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
        let result = checker.check(&domain).await;
        // Should be available (no DNS)
        assert!(result.available);
    }
}
