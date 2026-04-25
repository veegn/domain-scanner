use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, RwLock};
use tokio::time::Instant;
use tracing::{debug, info, warn};

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
    cache_path: Arc<PathBuf>,
    cache_entries: Arc<Mutex<HashMap<String, WhoisRateLimitCacheEntry>>>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WhoisRateLimitCacheFile {
    #[serde(default)]
    servers: HashMap<String, WhoisRateLimitCacheEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WhoisRateLimitCacheEntry {
    min_interval_ms: u64,
    updated_at_epoch_secs: u64,
    cooldown_until_epoch_secs: Option<u64>,
}

impl WhoisServerThrottle {
    fn new() -> Self {
        Self {
            min_interval: Duration::from_millis(250),
            next_allowed_at: Instant::now(),
        }
    }

    fn from_cache(entry: &WhoisRateLimitCacheEntry) -> Self {
        let min_interval = Duration::from_millis(entry.min_interval_ms.max(250));
        let mut next_allowed_at = Instant::now();
        if let Some(cooldown_until_epoch_secs) = entry.cooldown_until_epoch_secs {
            let remaining_secs = cooldown_until_epoch_secs.saturating_sub(now_epoch_secs());
            if remaining_secs > 0 {
                next_allowed_at += Duration::from_secs(remaining_secs);
            }
        }

        Self {
            min_interval,
            next_allowed_at,
        }
    }
}

impl WhoisChecker {
    pub fn new() -> Self {
        Self::with_servers(HashMap::new())
    }

    pub fn with_servers(custom_servers: HashMap<String, String>) -> Self {
        let cache_path = default_rate_limit_cache_path();
        let (cache_entries, initial_throttles) = load_cached_throttles(&cache_path);
        if !cache_entries.is_empty() {
            info!(
                target: "domain_scanner::checker::whois",
                context = "rate_limit_cache",
                path = %cache_path.display(),
                servers = cache_entries.len(),
                "loaded WHOIS rate-limit cache"
            );
        }

        Self {
            ip_cache: Arc::new(RwLock::new(HashMap::new())),
            server_map: Arc::new(normalize_server_map(custom_servers)),
            cb: Arc::new(CircuitBreaker::new(5, 120)),
            throttle_map: Arc::new(RwLock::new(initial_throttles)),
            cache_path: Arc::new(cache_path),
            cache_entries: Arc::new(Mutex::new(cache_entries)),
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
                debug!(
                    target: "domain_scanner::checker::whois",
                    context = "throttle",
                    server,
                    delay_ms = delay.as_millis() as u64,
                    "waiting for WHOIS throttle window"
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
        let mut changed = false;
        if guard.min_interval.as_millis() as u64 > floor_ms {
            let reduced_ms = ((guard.min_interval.as_millis() as u64) * 8 / 10).max(floor_ms);
            guard.min_interval = Duration::from_millis(reduced_ms);
            changed = true;
        }
        let min_interval = guard.min_interval;
        let cooldown_until = guard.next_allowed_at;
        drop(guard);

        if changed {
            self.persist_rate_limit_cache(server, min_interval, cooldown_until)
                .await;
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
        warn!(
            target: "domain_scanner::checker::whois",
            context = "backoff",
            server,
            reason = "timeout",
            min_interval_ms = guard.min_interval.as_millis() as u64,
            retry_after_secs = retry_after.as_secs(),
            "WHOIS timeout backoff updated"
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
        let min_interval = guard.min_interval;
        let next_allowed_at = guard.next_allowed_at;
        let should_persist = hint.retry_after.is_some() || hint.min_interval.is_some();
        drop(guard);

        if should_persist {
            self.persist_rate_limit_cache(server, min_interval, next_allowed_at)
                .await;
        }
        warn!(
            target: "domain_scanner::checker::whois",
            context = "backoff",
            server,
            reason = "rate_limit",
            min_interval_ms = min_interval.as_millis() as u64,
            retry_after_secs = retry_after.as_secs(),
            "WHOIS rate-limit backoff updated"
        );
        retry_after
    }

    async fn persist_rate_limit_cache(
        &self,
        server: &str,
        min_interval: Duration,
        next_allowed_at: Instant,
    ) {
        let cooldown_secs = next_allowed_at
            .checked_duration_since(Instant::now())
            .map(|duration| duration.as_secs())
            .filter(|secs| *secs > 0);

        let mut guard = self.cache_entries.lock().await;
        guard.insert(
            server.to_string(),
            WhoisRateLimitCacheEntry {
                min_interval_ms: min_interval.as_millis() as u64,
                updated_at_epoch_secs: now_epoch_secs(),
                cooldown_until_epoch_secs: cooldown_secs
                    .map(|secs| now_epoch_secs().saturating_add(secs)),
            },
        );
        let snapshot = guard.clone();
        drop(guard);

        write_rate_limit_cache(&self.cache_path, &snapshot);
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
        warn!(
            target: "domain_scanner::checker::whois",
            context = "dns",
            server_host,
            "failed to resolve WHOIS server host"
        );
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

    fn is_registered(&self, response: &str) -> bool {
        let lower = response.to_ascii_lowercase();
        [
            "domain name:",
            "registrar:",
            "registered on:",
            "registration time:",
            "creation date:",
            "expiry date:",
            "expiration date:",
            "domain status:",
            "name servers:",
        ]
        .iter()
        .any(|marker| lower.contains(marker))
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

fn normalize_server_map(custom_servers: HashMap<String, String>) -> HashMap<String, String> {
    let mut normalized = HashMap::new();
    for (tld, endpoint) in custom_servers {
        let normalized_tld = tld.trim().trim_start_matches('.').to_ascii_lowercase();
        let normalized_endpoint = endpoint.trim().to_string();
        if !normalized_tld.is_empty() && !normalized_endpoint.is_empty() {
            normalized.insert(normalized_tld, normalized_endpoint);
        }
    }
    normalized
}

fn load_cached_throttles(
    cache_path: &Path,
) -> (
    HashMap<String, WhoisRateLimitCacheEntry>,
    HashMap<String, Arc<Mutex<WhoisServerThrottle>>>,
) {
    let cache_entries = read_rate_limit_cache(cache_path);
    let throttles = cache_entries
        .iter()
        .map(|(server, entry)| {
            (
                server.clone(),
                Arc::new(Mutex::new(WhoisServerThrottle::from_cache(entry))),
            )
        })
        .collect();
    (cache_entries, throttles)
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
            return CheckResult::available().with_trace(format!("WHOIS: no server for {}", suffix));
        };

        match self.query_whois(domain, server).await {
            Ok(response) => {
                let response = response.trim();

                if response.is_empty() {
                    self.cb.record_failure();
                    warn!(
                        target: "domain_scanner::checker::whois",
                        context = "query",
                        domain,
                        server,
                        "WHOIS returned empty response"
                    );
                    return CheckResult::error(format!(
                        "WHOIS returned empty response from {}",
                        server
                    ))
                    .with_trace(format!("WHOIS: empty response via {}", server));
                }

                if self.is_rate_limited(&response) {
                    self.cb.record_failure();
                    let hint = self.sniff_rate_limit_hint(&response);
                    let retry_after = self.record_rate_limit(server, hint).await;
                    warn!(
                        target: "domain_scanner::checker::whois",
                        context = "query",
                        domain,
                        server,
                        retry_after_secs = retry_after.as_secs(),
                        "WHOIS detected rate limit"
                    );
                    return CheckResult::rate_limited_with_retry(
                        format!("WHOIS rate limit exceeded on {}", server),
                        Some(retry_after.as_secs().max(1)),
                    )
                    .with_trace(format!("WHOIS: rate limited via {}", server));
                }

                if self.is_available(&response) {
                    self.cb.record_success();
                    self.record_success(server).await;
                    CheckResult::available().with_trace(format!("WHOIS: available via {}", server))
                } else if self.is_registered(&response) {
                    self.cb.record_success();
                    self.record_success(server).await;
                    let expiry = self.extract_expiry(&response);
                    CheckResult::registered_with_expiry(vec!["WHOIS".to_string()], expiry)
                        .with_trace(format!("WHOIS: registered via {}", server))
                } else {
                    self.cb.record_failure();
                    warn!(
                        target: "domain_scanner::checker::whois",
                        context = "query",
                        domain,
                        server,
                        response_preview = %response.chars().take(120).collect::<String>(),
                        "WHOIS returned inconclusive response"
                    );
                    CheckResult::error(format!("WHOIS inconclusive response from {}", server))
                        .with_trace(format!("WHOIS: inconclusive via {}", server))
                }
            }
            Err(e) => {
                self.cb.record_failure();
                if is_timeout_error(&e) {
                    let retry_after = self.record_timeout(server).await;
                    warn!(
                        target: "domain_scanner::checker::whois",
                        context = "query",
                        domain,
                        server,
                        error = %e,
                        retry_after_secs = retry_after.as_secs(),
                        "WHOIS timeout"
                    );
                    CheckResult::retryable_error(
                        format!("WHOIS timeout on {}: {}", server, e),
                        Some(retry_after.as_secs().max(1)),
                    )
                    .with_trace(format!("WHOIS: timeout via {}", server))
                } else {
                    debug!(
                        target: "domain_scanner::checker::whois",
                        context = "query",
                        domain,
                        server,
                        error = %e,
                        "WHOIS terminal error"
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

fn default_rate_limit_cache_path() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("data")
        .join("cache")
        .join("whois")
        .join("rate_limits.json")
}

fn read_rate_limit_cache(path: &Path) -> HashMap<String, WhoisRateLimitCacheEntry> {
    let Ok(content) = fs::read_to_string(path) else {
        return HashMap::new();
    };

    match serde_json::from_str::<WhoisRateLimitCacheFile>(&content) {
        Ok(cache) => cache
            .servers
            .into_iter()
            .filter(|(_, entry)| entry.min_interval_ms > 0)
            .collect(),
        Err(err) => {
            warn!(
                target: "domain_scanner::checker::whois",
                context = "rate_limit_cache",
                path = %path.display(),
                error = %err,
                "failed to parse WHOIS rate-limit cache"
            );
            HashMap::new()
        }
    }
}

fn write_rate_limit_cache(path: &Path, servers: &HashMap<String, WhoisRateLimitCacheEntry>) {
    let Some(parent) = path.parent() else {
        return;
    };

    if let Err(err) = fs::create_dir_all(parent) {
        warn!(
            target: "domain_scanner::checker::whois",
            context = "rate_limit_cache",
            path = %parent.display(),
            error = %err,
            "failed to create WHOIS rate-limit cache directory"
        );
        return;
    }

    let serialized = match serde_json::to_vec_pretty(&WhoisRateLimitCacheFile {
        servers: servers.clone(),
    }) {
        Ok(serialized) => serialized,
        Err(err) => {
            warn!(
                target: "domain_scanner::checker::whois",
                context = "rate_limit_cache",
                path = %path.display(),
                error = %err,
                "failed to serialize WHOIS rate-limit cache"
            );
            return;
        }
    };

    if let Err(err) = fs::write(path, serialized) {
        warn!(
            target: "domain_scanner::checker::whois",
            context = "rate_limit_cache",
            path = %path.display(),
            error = %err,
            "failed to write WHOIS rate-limit cache"
        );
    }
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registered_response_requires_markers() {
        let checker = WhoisChecker::new();
        let response = "Domain Name: GOOGLE.COM\nRegistrar: MarkMonitor Inc.\nName Server: NS1.GOOGLE.COM";
        assert!(checker.is_registered(response));
    }

    #[test]
    fn test_empty_response_is_not_registered() {
        let checker = WhoisChecker::new();
        assert!(!checker.is_registered(""));
        assert!(!checker.is_available(""));
    }

    #[test]
    fn test_free_response_still_detected_as_available() {
        let checker = WhoisChecker::new();
        assert!(checker.is_available("No match for domain \"4TB.UK\""));
        assert!(!checker.is_registered("No match for domain \"4TB.UK\""));
    }

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

    #[test]
    fn test_rate_limit_cache_round_trip() {
        let temp_dir = std::env::temp_dir().join(format!(
            "domain-scanner-whois-cache-{}",
            uuid::Uuid::new_v4()
        ));
        let path = temp_dir.join("rate_limits.json");

        let mut servers = HashMap::new();
        servers.insert(
            "whois.nic.li".to_string(),
            WhoisRateLimitCacheEntry {
                min_interval_ms: 1500,
                updated_at_epoch_secs: now_epoch_secs(),
                cooldown_until_epoch_secs: Some(now_epoch_secs().saturating_add(60)),
            },
        );

        write_rate_limit_cache(&path, &servers);
        let loaded = read_rate_limit_cache(&path);

        assert_eq!(loaded.get("whois.nic.li").unwrap().min_interval_ms, 1500);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(temp_dir);
    }
}
