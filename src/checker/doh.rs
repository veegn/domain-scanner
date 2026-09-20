//! DNS over HTTPS (DoH) Checker
//!
//! This checker uses DNS over HTTPS to quickly determine if a domain has DNS records.
//! If a domain has NS records, it's very likely registered.

use async_trait::async_trait;
use reqwest::header::HeaderMap;
use serde::Deserialize;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, warn};

use super::circuit_breaker::CircuitBreaker;
use super::traits::{CheckResult, CheckerPriority, DomainChecker, acquire_network_permit};

/// Default DoH server URL
pub const DEFAULT_DOH_SERVERS: &[&str] = &[
    "https://dns.alidns.com/resolve",
    "https://doh.pub/dns-query",
    "https://dns.google/resolve",
    "https://dns.cloudflare.com/dns-query",
    "https://doh.dns.sb/dns-query",
];

/// Shared HTTP client for DoH queries
static DOH_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
});

#[derive(Deserialize, Debug)]
struct DohAnswer {
    name: String,
    #[serde(rename = "type")]
    record_type: u16,
}

#[derive(Deserialize, Debug)]
struct DohQuestion {
    name: String,
    #[serde(rename = "type")]
    record_type: u16,
}

#[derive(Deserialize, Debug)]
struct DohResponse {
    #[serde(rename = "Status")]
    status: u16,
    #[serde(rename = "Question", default)]
    question: Vec<DohQuestion>,
    #[serde(rename = "Answer")]
    answer: Option<Vec<DohAnswer>>,
}

fn normalized_dns_name(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn validate_doh_response(response: &DohResponse, domain: &str) -> Result<bool, &'static str> {
    let requested = normalized_dns_name(domain);
    if !response.question.iter().any(|question| {
        question.record_type == 2 && normalized_dns_name(&question.name) == requested
    }) {
        return Err("DNS response question did not match the requested NS lookup");
    }
    // A matching NXDOMAIN is a successful DNS lookup with no NS evidence. It
    // neither trips the provider circuit nor establishes registration absence.
    if response.status == 3 {
        return Ok(false);
    }
    if response.status != 0 {
        return Err("DNS response status was not NOERROR or NXDOMAIN");
    }
    Ok(response
        .answer
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|answer| answer.record_type == 2 && normalized_dns_name(&answer.name) == requested))
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
    /// Circuit breakers are isolated per provider.
    breaker_map: Arc<RwLock<std::collections::HashMap<String, Arc<CircuitBreaker>>>>,
    throttle_map: Arc<RwLock<std::collections::HashMap<String, Arc<Mutex<DohServerThrottle>>>>>,
}

#[derive(Debug)]
struct DohServerThrottle {
    min_interval: Duration,
    next_allowed_at: Instant,
}

impl DohChecker {
    /// Create a new DoH checker with the default servers
    pub async fn new() -> Self {
        Self::with_servers(vec![]).await
    }

    /// Create a new DoH checker with custom servers (or defaults if empty).
    /// Providers are evaluated by real requests; startup itself performs no
    /// network I/O, which keeps boot and offline tests deterministic.
    pub async fn with_servers(mut servers: Vec<String>) -> Self {
        if servers.is_empty() {
            servers = DEFAULT_DOH_SERVERS.iter().map(|s| s.to_string()).collect();
        }
        servers.retain(|server| !server.trim().is_empty());
        servers.sort();
        servers.dedup();

        Self {
            servers,
            current_idx: AtomicUsize::new(0),
            breaker_map: Arc::new(RwLock::new(std::collections::HashMap::new())),
            throttle_map: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    async fn throttle_for_server(&self, server: &str) -> Arc<Mutex<DohServerThrottle>> {
        {
            let guard = self.throttle_map.read().await;
            if let Some(existing) = guard.get(server) {
                return existing.clone();
            }
        }

        let mut guard = self.throttle_map.write().await;
        guard
            .entry(server.to_string())
            .or_insert_with(|| {
                Arc::new(Mutex::new(DohServerThrottle {
                    min_interval: Duration::from_millis(1_000),
                    next_allowed_at: Instant::now(),
                }))
            })
            .clone()
    }

    async fn breaker_for_server(&self, server: &str) -> Arc<CircuitBreaker> {
        if let Some(existing) = self.breaker_map.read().await.get(server).cloned() {
            return existing;
        }
        self.breaker_map
            .write()
            .await
            .entry(server.to_string())
            .or_insert_with(|| Arc::new(CircuitBreaker::new(20, 30)))
            .clone()
    }

    async fn try_claim_turn(&self, server: &str) -> Result<(), Duration> {
        let throttle = self.throttle_for_server(server).await;
        let mut guard = throttle.lock().await;
        let now = Instant::now();
        if guard.next_allowed_at > now {
            return Err(guard.next_allowed_at - now);
        }
        guard.next_allowed_at = now + guard.min_interval;
        Ok(())
    }

    async fn server_delay(&self, server: &str) -> Duration {
        let throttle = self.throttle_for_server(server).await;
        let guard = throttle.lock().await;
        let delay = guard
            .next_allowed_at
            .saturating_duration_since(Instant::now());
        drop(guard);
        let breaker = self.breaker_for_server(server).await;
        delay.max(Duration::from_secs(breaker.retry_after_secs().unwrap_or(0)))
    }

    async fn select_server(&self) -> (&str, Duration) {
        let len = self.servers.len();
        let start = self.current_idx.fetch_add(1, Ordering::Relaxed);
        let mut selected = (&self.servers[start % len], Duration::MAX);
        for offset in 0..len {
            let idx = (start + offset) % len;
            let server = &self.servers[idx];
            let delay = self.server_delay(server).await;
            if delay.is_zero() {
                return (server, delay);
            }
            if delay < selected.1 {
                selected = (server, delay);
            }
        }

        (selected.0, selected.1)
    }

    async fn record_success(&self, server: &str) {
        let throttle = self.throttle_for_server(server).await;
        let mut guard = throttle.lock().await;
        let floor_ms = 1_000;
        if guard.min_interval.as_millis() as u64 > floor_ms {
            let reduced_ms = ((guard.min_interval.as_millis() as u64) * 8 / 10).max(floor_ms);
            guard.min_interval = Duration::from_millis(reduced_ms);
        }
    }

    async fn record_rate_limit(&self, server: &str, retry_after: Option<Duration>) -> Duration {
        let throttle = self.throttle_for_server(server).await;
        let mut guard = throttle.lock().await;
        let next_ms = ((guard.min_interval.as_millis() as u64) * 2).clamp(2_000, 60_000);
        guard.min_interval = Duration::from_millis(next_ms);
        let retry_after =
            retry_after.unwrap_or_else(|| Duration::from_secs(60).max(guard.min_interval));
        guard.next_allowed_at = guard.next_allowed_at.max(Instant::now() + retry_after);
        warn!(
            target: "domain_scanner::checker::doh",
            context = "backoff",
            server,
            min_interval_ms = guard.min_interval.as_millis() as u64,
            retry_after_secs = retry_after.as_secs(),
            "DoH rate-limit backoff updated"
        );
        retry_after
    }

    async fn record_transient_failure(
        &self,
        server: &str,
        retry_after: Option<Duration>,
    ) -> Duration {
        let throttle = self.throttle_for_server(server).await;
        let mut guard = throttle.lock().await;
        let next_ms = ((guard.min_interval.as_millis() as u64) * 2).clamp(1_000, 300_000);
        guard.min_interval = Duration::from_millis(next_ms);
        let retry_after =
            retry_after.unwrap_or_else(|| Duration::from_secs(30).max(guard.min_interval));
        guard.next_allowed_at = guard.next_allowed_at.max(Instant::now() + retry_after);
        warn!(
            target: "domain_scanner::checker::doh",
            context = "backoff",
            server,
            min_interval_ms = guard.min_interval.as_millis() as u64,
            retry_after_secs = retry_after.as_secs(),
            "DoH transient failure backoff updated"
        );
        retry_after
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
        if self.servers.is_empty() {
            warn!(
                target: "domain_scanner::checker::doh",
                context = "runtime",
                domain,
                "no DoH servers available"
            );
            return CheckResult::error("No DoH servers available")
                .with_trace("DoH: no servers available");
        }

        let (server, delay) = self.select_server().await;
        if !delay.is_zero() {
            return CheckResult::deferred("DoH providers cooling down", delay)
                .with_trace(format!("DoH: deferred until provider {} is ready", server));
        }
        let _permit = match acquire_network_permit() {
            Ok(permit) => permit,
            Err(_) => {
                return CheckResult::deferred(
                    "global network limiter busy",
                    Duration::from_secs(1),
                )
                .with_trace("DoH: global network limiter busy");
            }
        };
        let breaker = self.breaker_for_server(server).await;
        let Some(_circuit_request) = breaker.acquire_request() else {
            return CheckResult::deferred(
                "DoH provider circuit breaker open",
                Duration::from_secs(breaker.retry_after_secs().unwrap_or(1)),
            )
            .with_trace(format!("DoH: circuit breaker open for {}", server));
        };
        if let Err(delay) = self.try_claim_turn(server).await {
            return CheckResult::deferred("DoH provider cooling down", delay)
                .with_trace(format!("DoH: provider {} deferred", server));
        }

        let url = format!("{}?name={}.&type=NS", server, domain);

        let resp = match DOH_CLIENT
            .get(&url)
            .header("Accept", "application/dns-json")
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                breaker.record_failure();
                let retry_after = self.record_transient_failure(server, None).await;
                debug!(
                    target: "domain_scanner::checker::doh",
                    context = "request",
                    domain,
                    server,
                    error = %e,
                    "DoH request failed"
                );
                return CheckResult::retryable_error(
                    format!("DoH request failed: {}", e),
                    Some(retry_after.as_secs().max(1)),
                )
                .with_trace(format!("DoH: request error via {}", server));
            }
        };

        let retry_after = retry_after_from_headers(resp.headers());
        if !resp.status().is_success() {
            let status = resp.status();
            if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                breaker.record_failure();
                let retry_after = self.record_rate_limit(server, retry_after).await;
                warn!(
                    target: "domain_scanner::checker::doh",
                    context = "request",
                    domain,
                    server,
                    "DoH rate limited"
                );
                return CheckResult::rate_limited_with_retry(
                    "DoH rate limit exceeded (HTTP 429)",
                    Some(retry_after.as_secs().max(1)),
                )
                .with_trace(format!("DoH: HTTP 429 via {}", server));
            }
            if status.is_server_error() {
                breaker.record_failure();
                let retry_after = self.record_transient_failure(server, retry_after).await;
                return CheckResult::retryable_error(
                    format!("DoH returned transient HTTP {}", status),
                    Some(retry_after.as_secs().max(1)),
                )
                .with_trace(format!("DoH: HTTP {} via {}", status, server));
            }
            breaker.record_failure();
            debug!(
                target: "domain_scanner::checker::doh",
                context = "request",
                domain,
                server,
                status = %resp.status(),
                "DoH returned non-success HTTP"
            );
            // Non-429 HTTP errors (5xx, 403, 502...) mean we cannot determine registration status.
            // Return error so the pipeline falls through to RDAP/WHOIS for confirmation.
            return CheckResult::error(format!("DoH returned HTTP {}", resp.status()))
                .with_trace(format!("DoH: HTTP {} via {}", resp.status(), server));
        }

        let result: DohResponse = match resp.json().await {
            Ok(r) => r,
            Err(err) => {
                breaker.record_failure();
                debug!(
                    target: "domain_scanner::checker::doh",
                    context = "response",
                    domain,
                    server,
                    error = %err,
                    "DoH response parse failed"
                );
                // A malformed/unparseable response tells us nothing about
                // registration status. Return an error so the
                // pipeline falls through to RDAP/WHOIS for an authoritative
                // answer instead of emitting a false positive.
                return CheckResult::error(format!("DoH response parse failed: {}", err))
                    .with_trace(format!("DoH: parse failed via {}", server));
            }
        };

        if result.status == 2 {
            breaker.record_failure();
            let retry_after = self.record_transient_failure(server, None).await;
            return CheckResult::retryable_error(
                "DoH returned DNS SERVFAIL",
                Some(retry_after.as_secs().max(1)),
            )
            .with_trace(format!("DoH: DNS SERVFAIL via {}", server));
        }

        match validate_doh_response(&result, domain) {
            Ok(has_ns) => {
                breaker.record_success();
                self.record_success(server).await;
                if has_ns {
                    CheckResult::registered(vec!["DNS".to_string()])
                        .with_trace(format!("DoH: NS records found via {}", server))
                } else {
                    CheckResult::unknown().with_trace(format!(
                        "DoH: no matching NS records via {}; registration status remains unknown",
                        server
                    ))
                }
            }
            Err(reason) => {
                breaker.record_failure();
                CheckResult::error(reason)
                    .with_trace(format!("DoH: invalid DNS response via {}", server))
            }
        }
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
        // DNS presence is evidence of registration. DNS absence is inconclusive.
        result.has_registration_evidence()
    }
}

fn retry_after_from_headers(headers: &HeaderMap) -> Option<Duration> {
    let raw = headers
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim();
    if let Ok(secs) = raw.parse::<u64>() {
        return Some(Duration::from_secs(secs.max(1)));
    }

    let parsed = chrono::DateTime::parse_from_rfc2822(raw).ok()?;
    let now = chrono::Utc::now();
    let secs = parsed
        .with_timezone(&chrono::Utc)
        .signed_duration_since(now)
        .num_seconds();
    Some(Duration::from_secs(secs.max(1) as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn repeated_nxdomain_keeps_provider_healthy_and_remains_inconclusive() {
        let app = axum::Router::new().route(
            "/resolve",
            axum::routing::get(|| async {
                axum::Json(
                    serde_json::json!({"Status":3,"Question":[{"name":"example.test.","type":2}]}),
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = format!("http://{}/resolve", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let checker = DohChecker::with_servers(vec![server.clone()]).await;
        let throttle = checker.throttle_for_server(&server).await;
        for _ in 0..25 {
            throttle.lock().await.next_allowed_at = Instant::now();
            let result = checker.check("example.test").await;
            assert!(result.error.is_none(), "{:?}", result);
            assert!(!result.registration_record_absent);
            assert!(!result.has_registration_evidence());
        }
        assert_eq!(
            checker.breaker_for_server(&server).await.retry_after_secs(),
            None
        );
        handle.abort();
    }

    #[tokio::test]
    async fn selection_skips_open_circuit_and_cooldown_does_not_hold_global_capacity() {
        let checker = DohChecker::with_servers(vec![
            "http://broken.test".into(),
            "http://healthy.test".into(),
        ])
        .await;
        let breaker = checker.breaker_for_server("http://broken.test").await;
        for _ in 0..20 {
            breaker.record_failure();
        }
        assert_eq!(checker.select_server().await.0, "http://healthy.test");
        checker
            .throttle_for_server("http://healthy.test")
            .await
            .lock()
            .await
            .next_allowed_at = Instant::now() + Duration::from_secs(30);
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        let result = super::super::traits::with_network_permits(
            permits.clone(),
            checker.check("example.test"),
        )
        .await;
        assert!(result.deferred);
        assert_eq!(permits.available_permits(), 1);
    }

    #[test]
    fn validates_requested_ns_evidence() {
        let valid: DohResponse = serde_json::from_str(
            r#"{"Status":0,"Question":[{"name":"example.com.","type":2}],"Answer":[{"name":"example.com.","type":2}]}"#,
        ).unwrap();
        assert_eq!(validate_doh_response(&valid, "example.com"), Ok(true));

        let wrong_owner: DohResponse = serde_json::from_str(
            r#"{"Status":0,"Question":[{"name":"example.com.","type":2}],"Answer":[{"name":"other.com.","type":2}]}"#,
        ).unwrap();
        assert_eq!(
            validate_doh_response(&wrong_owner, "example.com"),
            Ok(false)
        );
    }

    #[test]
    fn rejects_mismatched_or_failed_dns_payloads() {
        let mismatch: DohResponse = serde_json::from_str(
            r#"{"Status":0,"Question":[{"name":"other.com.","type":2}],"Answer":[{"name":"example.com.","type":2}]}"#,
        ).unwrap();
        assert!(validate_doh_response(&mismatch, "example.com").is_err());

        let servfail: DohResponse =
            serde_json::from_str(r#"{"Status":2,"Question":[{"name":"example.com.","type":2}]}"#)
                .unwrap();
        assert!(validate_doh_response(&servfail, "example.com").is_err());
    }

    fn live_network_enabled() -> bool {
        std::env::var("DOMAIN_SCANNER_LIVE_TESTS")
            .map(|v| v == "1")
            .unwrap_or(false)
    }

    #[tokio::test]
    async fn test_doh_google_com() {
        if !live_network_enabled() {
            return;
        }

        let checker = DohChecker::new().await;
        // google.com has NS records
        let result = checker.check("google.com").await;
        // Should be registered (DNS signature)
        // Note: this test might fail if no internet or all doh block, but assuming dev env has net
        if result.registration_record_absent {
            // DoH must never claim authoritative record absence.
            if let Some(e) = result.error {
                debug!(
                    target: "domain_scanner::checker::doh",
                    context = "test",
                    error = %e,
                    "DoH check failed in live test"
                );
            }
        } else {
            assert!(result.signatures.contains(&"DNS".to_string()));
        }
    }

    #[tokio::test]
    async fn test_doh_nonexistent() {
        if !live_network_enabled() {
            return;
        }

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
        // DNS absence is inconclusive, not proof of registration-record absence.
        assert!(!result.registration_record_absent);
    }
}
