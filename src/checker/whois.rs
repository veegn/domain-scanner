use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, RwLock};
use tokio::time::Instant;

use super::circuit_breaker::CircuitBreaker;
use super::traits::{CheckResult, CheckerPriority, DomainChecker};

/// Pre-compiled WHOIS expiry date regexes (compiled once, reused on every WHOIS call).
static EXPIRY_REGEXES: OnceLock<Vec<regex::Regex>> = OnceLock::new();
static RETRY_AFTER_REGEXES: OnceLock<Vec<regex::Regex>> = OnceLock::new();
static RATE_REGEXES: OnceLock<Vec<regex::Regex>> = OnceLock::new();

fn expiry_regexes() -> &'static Vec<regex::Regex> {
    EXPIRY_REGEXES.get_or_init(|| {
        [
            r"(?i)Registry Expiry Date:\s*(.+)",
            r"(?i)Expiration Date:\s*(.+)",
            r"(?i)Expires on:\s*(.+)",
            r"(?i)Expiry date:\s*(.+)",
            r"(?i)paid-till:\s*(.+)",
            r"(?i)Record expires on\s*(.+)",
        ]
        .iter()
        .filter_map(|p| regex::Regex::new(p).ok())
        .collect()
    })
}

fn retry_after_regexes() -> &'static Vec<regex::Regex> {
    RETRY_AFTER_REGEXES.get_or_init(|| {
        [
            r"(?i)retry\s+after[:\s]+(\d+)\s*(seconds?|secs?|minutes?|mins?|hours?|hrs?)",
            r"(?i)wait\s+(\d+)\s*(seconds?|secs?|minutes?|mins?|hours?|hrs?)",
            r"(?i)try\s+again\s+in\s+(\d+)\s*(seconds?|secs?|minutes?|mins?|hours?|hrs?)",
        ]
        .iter()
        .filter_map(|p| regex::Regex::new(p).ok())
        .collect()
    })
}

fn rate_regexes() -> &'static Vec<regex::Regex> {
    RATE_REGEXES.get_or_init(|| {
        [
            r"(?i)(\d+)\s*quer(?:y|ies)\s+per\s+(second|minute|hour|day)",
            r"(?i)limit[:\s]+(\d+)\s*/\s*(second|minute|hour|day)",
        ]
        .iter()
        .filter_map(|p| regex::Regex::new(p).ok())
        .collect()
    })
}

/// WHOIS Checker with DNS caching and per-server adaptive throttling.
#[derive(Debug, Clone)]
pub struct WhoisChecker {
    ip_cache: Arc<RwLock<HashMap<String, IpAddr>>>,
    server_map: Arc<HashMap<String, String>>,
    cb: Arc<CircuitBreaker>,
    throttle_map: Arc<RwLock<HashMap<String, Arc<Mutex<WhoisServerThrottle>>>>>,
}

#[derive(Debug)]
struct WhoisServerThrottle {
    min_interval: Duration,
    next_allowed_at: Instant,
}

#[derive(Debug, Clone, Copy)]
struct RateLimitHint {
    retry_after: Option<Duration>,
    min_interval: Option<Duration>,
}

impl WhoisServerThrottle {
    fn new() -> Self {
        Self {
            min_interval: Duration::from_millis(250),
            next_allowed_at: Instant::now(),
        }
    }
}

impl WhoisChecker {
    pub fn new() -> Self {
        Self::with_servers(HashMap::new())
    }

    pub fn with_servers(custom_servers: HashMap<String, String>) -> Self {
        let mut m = HashMap::new();

        for (tld, endpoint) in custom_servers {
            let normalized_tld = tld.trim().trim_start_matches('.').to_ascii_lowercase();
            let normalized_endpoint = endpoint.trim().to_string();
            if !normalized_tld.is_empty() && !normalized_endpoint.is_empty() {
                m.insert(normalized_tld, normalized_endpoint);
            }
        }

        Self {
            ip_cache: Arc::new(RwLock::new(HashMap::new())),
            server_map: Arc::new(m),
            cb: Arc::new(CircuitBreaker::new(5, 120)),
            throttle_map: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn throttle_for_server(&self, server: &str) -> Arc<Mutex<WhoisServerThrottle>> {
        {
            let guard = self.throttle_map.read().await;
            if let Some(existing) = guard.get(server) {
                return existing.clone();
            }
        }

        let mut guard = self.throttle_map.write().await;
        guard
            .entry(server.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(WhoisServerThrottle::new())))
            .clone()
    }

    async fn wait_for_turn(&self, server: &str) {
        let throttle = self.throttle_for_server(server).await;
        loop {
            let sleep_for = {
                let mut guard = throttle.lock().await;
                let now = Instant::now();
                if guard.next_allowed_at <= now {
                    guard.next_allowed_at = now + guard.min_interval;
                    None
                } else {
                    Some(guard.next_allowed_at - now)
                }
            };

            if let Some(delay) = sleep_for {
                println!(
                    "WHOIS throttling server {} for {}ms before next request",
                    server,
                    delay.as_millis()
                );
                tokio::time::sleep(delay).await;
            } else {
                break;
            }
        }
    }

    async fn record_success(&self, server: &str) {
        let throttle = self.throttle_for_server(server).await;
        let mut guard = throttle.lock().await;
        let floor_ms = 250;
        if guard.min_interval.as_millis() as u64 > floor_ms {
            let reduced_ms = ((guard.min_interval.as_millis() as u64) * 8 / 10).max(floor_ms);
            guard.min_interval = Duration::from_millis(reduced_ms);
        }
    }

    async fn record_timeout(&self, server: &str) -> Duration {
        let throttle = self.throttle_for_server(server).await;
        let mut guard = throttle.lock().await;
        let next_ms = ((guard.min_interval.as_millis() as u64) * 2)
            .max(1_000)
            .min(30_000);
        guard.min_interval = Duration::from_millis(next_ms);
        let retry_after = Duration::from_secs(30).max(guard.min_interval);
        guard.next_allowed_at = Instant::now() + retry_after;
        eprintln!(
            "WHOIS timeout backoff updated for {}: min_interval={}ms retry_after={}s",
            server,
            guard.min_interval.as_millis(),
            retry_after.as_secs()
        );
        retry_after
    }

    async fn record_rate_limit(&self, server: &str, hint: RateLimitHint) -> Duration {
        let throttle = self.throttle_for_server(server).await;
        let mut guard = throttle.lock().await;

        if let Some(min_interval) = hint.min_interval {
            guard.min_interval = guard.min_interval.max(min_interval);
        } else {
            let next_ms = ((guard.min_interval.as_millis() as u64) * 2)
                .max(2_000)
                .min(60_000);
            guard.min_interval = Duration::from_millis(next_ms);
        }

        let retry_after = hint
            .retry_after
            .unwrap_or_else(|| Duration::from_secs(60).max(guard.min_interval));
        guard.next_allowed_at = Instant::now() + retry_after;
        eprintln!(
            "WHOIS rate limit backoff updated for {}: min_interval={}ms retry_after={}s",
            server,
            guard.min_interval.as_millis(),
            retry_after.as_secs()
        );
        retry_after
    }

    async fn resolve_server(&self, server_host: &str) -> Option<IpAddr> {
        {
            let cache = self.ip_cache.read().await;
            if let Some(&ip) = cache.get(server_host) {
                return Some(ip);
            }
        }

        let addr_str = format!("{}:43", server_host);

        match tokio::net::lookup_host(&addr_str).await {
            Ok(mut addrs) => {
                if let Some(addr) = addrs.next() {
                    let ip = addr.ip();
                    let mut cache = self.ip_cache.write().await;
                    cache.insert(server_host.to_string(), ip);
                    return Some(ip);
                }
            }
            Err(_) => {}
        }
        eprintln!("WHOIS failed to resolve server host {}", server_host);
        None
    }

    async fn query_whois(&self, domain: &str, server: &str) -> Result<String, String> {
        self.wait_for_turn(server).await;

        let (server_host, server_port) = parse_server_endpoint(server);
        let ip = self
            .resolve_server(&server_host)
            .await
            .ok_or_else(|| format!("Could not resolve WHOIS server IP for {}", server_host))?;

        let stream_future = TcpStream::connect((ip, server_port));
        let mut stream = tokio::time::timeout(Duration::from_secs(3), stream_future)
            .await
            .map_err(|_| "Connection timeout".to_string())?
            .map_err(|e| format!("Connection failed: {}", e))?;

        let query = format!("{}\r\n", domain);
        stream
            .write_all(query.as_bytes())
            .await
            .map_err(|e| format!("Send failed: {}", e))?;

        let mut buffer = String::new();
        let read_future = stream.read_to_string(&mut buffer);

        tokio::time::timeout(Duration::from_secs(10), read_future)
            .await
            .map_err(|_| "Read timeout".to_string())?
            .map_err(|e| format!("Read failed: {}", e))?;

        Ok(buffer)
    }

    fn is_available(&self, response: &str) -> bool {
        let lower = response.to_lowercase();
        lower.contains("no match")
            || lower.contains("not found")
            || lower.contains("no entries found")
            || lower.contains("status: free")
            || lower.contains("domain not found")
            || lower.contains("no matching record")
    }

    fn is_rate_limited(&self, response: &str) -> bool {
        let lower = response.to_lowercase();
        lower.contains("limit exceeded")
            || lower.contains("quota exceeded")
            || lower.contains("too many requests")
            || lower.contains("blacklist")
            || lower.contains("access denied")
    }

    fn sniff_rate_limit_hint(&self, response: &str) -> RateLimitHint {
        let retry_after = retry_after_regexes().iter().find_map(|re| {
            let captures = re.captures(response)?;
            let value = captures.get(1)?.as_str().parse::<u64>().ok()?;
            let unit = captures.get(2)?.as_str();
            Some(duration_from_unit(value, unit))
        });

        let min_interval = rate_regexes().iter().find_map(|re| {
            let captures = re.captures(response)?;
            let value = captures.get(1)?.as_str().parse::<u64>().ok()?;
            let unit = captures.get(2)?.as_str();
            queries_per_window_to_interval(value, unit)
        });

        RateLimitHint {
            retry_after,
            min_interval,
        }
    }

    fn extract_expiry(&self, response: &str) -> Option<String> {
        for re in expiry_regexes() {
            if let Some(caps) = re.captures(response) {
                if let Some(m) = caps.get(1) {
                    return Some(m.as_str().trim().to_string());
                }
            }
        }
        None
    }
}

impl Default for WhoisChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DomainChecker for WhoisChecker {
    fn name(&self) -> &'static str {
        "WHOIS"
    }

    fn priority(&self) -> CheckerPriority {
        CheckerPriority::Fallback
    }

    async fn check(&self, domain: &str) -> CheckResult {
        if !self.cb.allow_request() {
            eprintln!("WHOIS circuit breaker open for domain {}", domain);
            return CheckResult::rate_limited_with_retry("WHOIS circuit breaker open", Some(60))
                .with_trace("WHOIS: circuit breaker open");
        }

        let suffix = if let Some(suffix) = self.matching_suffix(domain) {
            suffix
        } else if domain.contains('.') {
            return CheckResult::available().with_trace("WHOIS: unsupported suffix");
        } else {
            return CheckResult::error("Invalid domain").with_trace("WHOIS: invalid domain");
        };

        let server = if let Some(s) = self.server_map.get(&suffix) {
            s.as_str()
        } else {
            println!(
                "WHOIS skipped unsupported suffix {} for domain {}",
                suffix, domain
            );
            return CheckResult::available().with_trace(format!("WHOIS: no server for {}", suffix));
        };

        match self.query_whois(domain, server).await {
            Ok(response) => {
                if self.is_rate_limited(&response) {
                    self.cb.record_failure();
                    let hint = self.sniff_rate_limit_hint(&response);
                    let retry_after = self.record_rate_limit(server, hint).await;
                    eprintln!(
                        "WHOIS detected rate limit for domain {} via server {}",
                        domain, server
                    );
                    return CheckResult::rate_limited_with_retry(
                        format!("WHOIS rate limit exceeded on {}", server),
                        Some(retry_after.as_secs().max(1)),
                    )
                    .with_trace(format!("WHOIS: rate limited via {}", server));
                }

                self.cb.record_success();
                self.record_success(server).await;

                if self.is_available(&response) {
                    println!("WHOIS marked domain {} as available via {}", domain, server);
                    CheckResult::available().with_trace(format!("WHOIS: available via {}", server))
                } else {
                    let expiry = self.extract_expiry(&response);
                    println!(
                        "WHOIS marked domain {} as registered via {}",
                        domain, server
                    );
                    CheckResult::registered_with_expiry(vec!["WHOIS".to_string()], expiry)
                        .with_trace(format!("WHOIS: registered via {}", server))
                }
            }
            Err(e) => {
                self.cb.record_failure();
                if is_timeout_error(&e) {
                    let retry_after = self.record_timeout(server).await;
                    eprintln!(
                        "WHOIS timeout for domain {} via server {}: {}",
                        domain, server, e
                    );
                    CheckResult::retryable_error(
                        format!("WHOIS timeout on {}: {}", server, e),
                        Some(retry_after.as_secs().max(1)),
                    )
                    .with_trace(format!("WHOIS: timeout via {}", server))
                } else {
                    eprintln!(
                        "WHOIS terminal error for domain {} via server {}: {}",
                        domain, server, e
                    );
                    CheckResult::error(format!("WHOIS: {}", e))
                        .with_trace(format!("WHOIS: error via {}", server))
                }
            }
        }
    }

    fn supports_tld(&self, tld: &str) -> bool {
        self.server_map.contains_key(tld)
    }

    fn is_authoritative(&self) -> bool {
        true
    }
}

fn parse_server_endpoint(endpoint: &str) -> (String, u16) {
    if let Some((host, port)) = endpoint.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            return (host.to_string(), port);
        }
    }

    (endpoint.to_string(), 43)
}

fn is_timeout_error(error: &str) -> bool {
    error.to_ascii_lowercase().contains("timeout")
}

fn duration_from_unit(value: u64, unit: &str) -> Duration {
    let lower = unit.to_ascii_lowercase();
    let secs = if lower.starts_with("hour") || lower.starts_with("hr") {
        value.saturating_mul(60 * 60)
    } else if lower.starts_with("minute") || lower.starts_with("min") {
        value.saturating_mul(60)
    } else {
        value
    };
    Duration::from_secs(secs.max(1))
}

fn queries_per_window_to_interval(limit: u64, unit: &str) -> Option<Duration> {
    if limit == 0 {
        return None;
    }

    let window_secs = match unit.to_ascii_lowercase().as_str() {
        "second" => 1,
        "minute" => 60,
        "hour" => 60 * 60,
        "day" => 60 * 60 * 24,
        _ => return None,
    };

    let per_query_secs = ((window_secs as f64) / (limit as f64)).ceil() as u64;
    Some(Duration::from_secs(per_query_secs.max(1)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sniff_rate_limit_hint_parses_retry_after_and_qpm() {
        let checker = WhoisChecker::new();
        let hint = checker.sniff_rate_limit_hint(
            "Query limit exceeded. Retry after 5 minutes. Limit: 60 queries per hour.",
        );

        assert_eq!(hint.retry_after, Some(Duration::from_secs(300)));
        assert_eq!(hint.min_interval, Some(Duration::from_secs(60)));
    }

    #[test]
    fn test_queries_per_window_to_interval_handles_minutes() {
        assert_eq!(
            queries_per_window_to_interval(30, "minute"),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            queries_per_window_to_interval(120, "hour"),
            Some(Duration::from_secs(30))
        );
    }
}
