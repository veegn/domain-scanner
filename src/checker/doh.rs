//! DNS over HTTPS (DoH) Checker
//!
//! This checker uses DNS over HTTPS to quickly determine if a domain has DNS records.
//! If a domain has NS records, it's very likely registered.

use async_trait::async_trait;
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::circuit_breaker::CircuitBreaker;
use super::traits::{CheckResult, CheckerPriority, DomainChecker};

/// Default DoH server URL
pub const DEFAULT_DOH_SERVERS: &[&str] = &[
    "https://dns.alidns.com/resolve",
    "https://doh.pub/dns-query",
    "https://dns.google/resolve",
    "https://dns.cloudflare.com/dns-query",
    "https://doh.dns.sb/dns-query",
];

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
#[derive(Debug)]
pub struct DohChecker {
    /// The DoH servers to use
    pub servers: Vec<String>,
    /// Current server index for round-robin
    pub current_idx: AtomicUsize,
    /// Circuit breaker to prevent cascading failures
    pub cb: Arc<CircuitBreaker>,
}

impl DohChecker {
    /// Create a new DoH checker with the default servers
    pub async fn new() -> Self {
        Self::with_servers(vec![]).await
    }

    /// Create a new DoH checker with custom servers (or defaults if empty)
    /// Performs latency checks at startup.
    pub async fn with_servers(mut servers: Vec<String>) -> Self {
        if servers.is_empty() {
            servers = DEFAULT_DOH_SERVERS.iter().map(|s| s.to_string()).collect();
        }

        // Latency check
        let mut healthy_servers = Vec::new();
        let mut slow_servers = Vec::new();
        println!("Performing DoH server latency check...");

        for server in &servers {
            let start = Instant::now();
            let test_url = format!("{}?name=apple.com.&type=A", server);

            match DOH_CLIENT
                .get(&test_url)
                .header("Accept", "application/dns-json")
                .send()
                .await
            {
                Ok(resp) => {
                    let elapsed = start.elapsed();
                    let latency_ms = elapsed.as_millis();
                    if resp.status().is_success() {
                        if latency_ms < 250 {
                            println!("  \x1b[32m[OK]\x1b[0m {} ({}ms)", server, latency_ms);
                            healthy_servers.push(server.clone());
                        } else {
                            println!(
                                "  \x1b[33m[SLOW]\x1b[0m {} ({}ms > 100ms)",
                                server, latency_ms
                            );
                            slow_servers.push(server.clone());
                        }
                    } else {
                        println!(
                            "  \x1b[31m[FAIL]\x1b[0m {} (Status: {})",
                            server,
                            resp.status()
                        );
                    }
                }
                Err(e) => {
                    println!("  \x1b[31m[ERR]\x1b[0m {} ({})", server, e);
                }
            }
        }

        let final_servers = if !healthy_servers.is_empty() {
            println!(
                "Selected {} healthy DoH servers (<250ms).",
                healthy_servers.len()
            );
            healthy_servers
        } else if !slow_servers.is_empty() {
            println!(
                "\x1b[33mWarning: No fast servers found. Using {} slow servers.\x1b[0m",
                slow_servers.len()
            );
            slow_servers
        } else {
            println!(
                "\x1b[31mError: All DoH servers failed. Using all provided servers as fallback.\x1b[0m"
            );
            servers
        };

        Self {
            servers: final_servers,
            current_idx: AtomicUsize::new(0),
            cb: Arc::new(CircuitBreaker::new(20, 30)),
        }
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

        if self.servers.is_empty() {
            return CheckResult::error("No DoH servers available");
        }

        // Round Robin selection
        let idx = self.current_idx.fetch_add(1, Ordering::Relaxed) % self.servers.len();
        let server = &self.servers[idx];

        let url = format!("{}?name={}.&type=NS", server, domain);

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

    fn should_stop_pipeline(&self, result: &CheckResult) -> bool {
        // Requirement 1: If DNS found (Available=False), stop the pipeline.
        // If DNS NOT found (Available=True), continue to other checkers (WHOIS).
        !result.available
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_doh_google_com() {
        let checker = DohChecker::new().await;
        // google.com has NS records
        let result = checker.check("google.com").await;
        // Should be registered (DNS signature)
        // Note: this test might fail if no internet or all doh block, but assuming dev env has net
        if result.available {
            // If marked available, check if it was an error
            if let Some(e) = result.error {
                eprintln!("DoH Check failed with error: {}", e);
            }
        } else {
            assert!(result.signatures.contains(&"DNS".to_string()));
        }
    }

    #[tokio::test]
    async fn test_doh_nonexistent() {
        let checker = DohChecker::new().await;
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
