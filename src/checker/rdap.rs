use std::collections::HashMap;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use tokio::sync::{Mutex, RwLock};
use tokio::time::Instant;
use tracing::{debug, info, warn};

use super::circuit_breaker::CircuitBreaker;
use super::traits::{CheckResult, CheckerPriority, DomainChecker};

static RDAP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .unwrap()
});

const RDAP_BOOTSTRAP_CACHE_TTL_SECS: u64 = 24 * 60 * 60;
const BUILTIN_RDAP_ENDPOINTS: &[(&str, &str)] = &[
    ("uk", "https://rdap.nominet.uk/uk/"),
    ("co.uk", "https://rdap.nominet.uk/uk/"),
    ("org.uk", "https://rdap.nominet.uk/uk/"),
    ("me.uk", "https://rdap.nominet.uk/uk/"),
];

#[derive(Debug, Clone)]
pub struct RdapChecker {
    endpoint_map: Arc<HashMap<String, String>>,
    cb: Arc<CircuitBreaker>,
    throttle_map: Arc<RwLock<HashMap<String, Arc<Mutex<RdapEndpointThrottle>>>>>,
    throttle_cache_path: Arc<PathBuf>,
    throttle_cache_entries: Arc<Mutex<HashMap<String, RdapRateLimitCacheEntry>>>,
}

#[derive(Debug)]
struct RdapEndpointThrottle {
    min_interval: Duration,
    next_allowed_at: Instant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RdapRateLimitCacheFile {
    #[serde(default)]
    endpoints: HashMap<String, RdapRateLimitCacheEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RdapRateLimitCacheEntry {
    min_interval_ms: u64,
    updated_at_epoch_secs: u64,
    cooldown_until_epoch_secs: Option<u64>,
}

impl RdapEndpointThrottle {
    fn from_cache(entry: &RdapRateLimitCacheEntry) -> Self {
        let min_interval = Duration::from_millis(entry.min_interval_ms.max(1_000));
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

#[derive(Debug, Deserialize)]
struct BootstrapDocument {
    services: Vec<(Vec<String>, Vec<String>)>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BootstrapCacheFile {
    source_url: String,
    fetched_at_epoch_secs: u64,
    endpoint_map: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct RdapDomainResponse {
    #[serde(default)]
    events: Vec<RdapEvent>,
}

#[derive(Debug, Deserialize)]
struct RdapEvent {
    #[serde(rename = "eventAction")]
    event_action: Option<String>,
    #[serde(rename = "eventDate")]
    event_date: Option<String>,
}

impl RdapChecker {
    pub async fn new() -> Self {
        Self::with_config(HashMap::new(), None).await
    }

    pub async fn with_config(
        custom_endpoints: HashMap<String, String>,
        bootstrap_url: Option<String>,
    ) -> Self {
        Self::with_config_and_cache_dir(custom_endpoints, bootstrap_url, None).await
    }

    pub async fn with_config_and_cache_dir(
        custom_endpoints: HashMap<String, String>,
        bootstrap_url: Option<String>,
        cache_dir: Option<PathBuf>,
    ) -> Self {
        let mut endpoint_map = builtin_endpoint_map();

        if let Some(url) = bootstrap_url.filter(|url| !url.trim().is_empty()) {
            match fetch_bootstrap_map_with_cache(&url, cache_dir.as_deref()).await {
                Ok(bootstrap_endpoints) => {
                    info!(
                        target: "domain_scanner::checker::rdap",
                        context = "bootstrap",
                        source = %url,
                        mappings = bootstrap_endpoints.len(),
                        "RDAP bootstrap loaded"
                    );
                    for (suffix, endpoint) in bootstrap_endpoints {
                        endpoint_map.entry(suffix).or_insert(endpoint);
                    }
                }
                Err(err) => {
                    warn!(
                        target: "domain_scanner::checker::rdap",
                        context = "bootstrap",
                        source = %url,
                        error = %err,
                        "failed to load RDAP bootstrap"
                    );
                }
            }
        }

        endpoint_map.extend(normalize_endpoint_map(custom_endpoints));
        let throttle_cache_path = default_rdap_rate_limit_cache_path();
        let (throttle_cache_entries, initial_throttles) =
            load_cached_rdap_throttles(&throttle_cache_path);
        if !throttle_cache_entries.is_empty() {
            info!(
                target: "domain_scanner::checker::rdap",
                context = "rate_limit_cache",
                path = %throttle_cache_path.display(),
                endpoints = throttle_cache_entries.len(),
                "loaded RDAP rate-limit cache"
            );
        }

        Self {
            endpoint_map: Arc::new(endpoint_map),
            cb: Arc::new(CircuitBreaker::new(10, 60)),
            throttle_map: Arc::new(RwLock::new(initial_throttles)),
            throttle_cache_path: Arc::new(throttle_cache_path),
            throttle_cache_entries: Arc::new(Mutex::new(throttle_cache_entries)),
        }
    }

    fn endpoint_for_domain(&self, domain: &str) -> Option<(String, String)> {
        self.matching_suffix(domain).and_then(|suffix| {
            self.endpoint_map
                .get(&suffix)
                .cloned()
                .map(|endpoint| (suffix, endpoint))
        })
    }

    fn extract_expiry(response: &RdapDomainResponse) -> Option<String> {
        response.events.iter().find_map(|event| {
            let action = event.event_action.as_deref()?.to_ascii_lowercase();
            let is_expiry = action.contains("expiration") || action.contains("expiry");
            if is_expiry {
                event.event_date.clone()
            } else {
                None
            }
        })
    }

    async fn throttle_for_endpoint(&self, endpoint: &str) -> Arc<Mutex<RdapEndpointThrottle>> {
        {
            let guard = self.throttle_map.read().await;
            if let Some(existing) = guard.get(endpoint) {
                return existing.clone();
            }
        }

        let mut guard = self.throttle_map.write().await;
        guard
            .entry(endpoint.to_string())
            .or_insert_with(|| {
                Arc::new(Mutex::new(RdapEndpointThrottle {
                    min_interval: Duration::from_millis(1_000),
                    next_allowed_at: Instant::now(),
                }))
            })
            .clone()
    }

    async fn wait_for_turn(&self, endpoint: &str) {
        let throttle = self.throttle_for_endpoint(endpoint).await;
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
                    target: "domain_scanner::checker::rdap",
                    context = "throttle",
                    endpoint,
                    delay_ms = delay.as_millis() as u64,
                    "waiting for RDAP throttle window"
                );
                tokio::time::sleep(delay).await;
            } else {
                break;
            }
        }
    }

    async fn record_success(&self, endpoint: &str) {
        let throttle = self.throttle_for_endpoint(endpoint).await;
        let mut guard = throttle.lock().await;
        let floor_ms = 1_000;
        if guard.min_interval.as_millis() as u64 > floor_ms {
            let reduced_ms = ((guard.min_interval.as_millis() as u64) * 8 / 10).max(floor_ms);
            guard.min_interval = Duration::from_millis(reduced_ms);
        }
    }

    async fn record_rate_limit(&self, endpoint: &str, retry_after: Option<Duration>) -> Duration {
        let throttle = self.throttle_for_endpoint(endpoint).await;
        let mut guard = throttle.lock().await;
        let next_ms = ((guard.min_interval.as_millis() as u64) * 2)
            .max(2_000)
            .min(60_000);
        guard.min_interval = Duration::from_millis(next_ms);
        let retry_after =
            retry_after.unwrap_or_else(|| Duration::from_secs(60).max(guard.min_interval));
        guard.next_allowed_at = Instant::now() + retry_after;
        warn!(
            target: "domain_scanner::checker::rdap",
            context = "backoff",
            endpoint,
            min_interval_ms = guard.min_interval.as_millis() as u64,
            retry_after_secs = retry_after.as_secs(),
            "RDAP rate-limit backoff updated"
        );
        let min_interval = guard.min_interval;
        let next_allowed_at = guard.next_allowed_at;
        drop(guard);
        self.persist_rate_limit_cache(endpoint, min_interval, next_allowed_at)
            .await;
        retry_after
    }

    async fn record_transient_failure(
        &self,
        endpoint: &str,
        retry_after: Option<Duration>,
    ) -> Duration {
        let throttle = self.throttle_for_endpoint(endpoint).await;
        let mut guard = throttle.lock().await;
        let next_ms = ((guard.min_interval.as_millis() as u64) * 2)
            .max(1_000)
            .min(30_000);
        guard.min_interval = Duration::from_millis(next_ms);
        let retry_after =
            retry_after.unwrap_or_else(|| Duration::from_secs(30).max(guard.min_interval));
        guard.next_allowed_at = Instant::now() + retry_after;
        warn!(
            target: "domain_scanner::checker::rdap",
            context = "backoff",
            endpoint,
            min_interval_ms = guard.min_interval.as_millis() as u64,
            retry_after_secs = retry_after.as_secs(),
            "RDAP transient failure backoff updated"
        );
        let min_interval = guard.min_interval;
        let next_allowed_at = guard.next_allowed_at;
        drop(guard);
        self.persist_rate_limit_cache(endpoint, min_interval, next_allowed_at)
            .await;
        retry_after
    }

    async fn persist_rate_limit_cache(
        &self,
        endpoint: &str,
        min_interval: Duration,
        next_allowed_at: Instant,
    ) {
        let cooldown_secs = next_allowed_at
            .checked_duration_since(Instant::now())
            .map(|duration| duration.as_secs())
            .filter(|secs| *secs > 0);

        let mut guard = self.throttle_cache_entries.lock().await;
        guard.insert(
            endpoint.to_string(),
            RdapRateLimitCacheEntry {
                min_interval_ms: min_interval.as_millis() as u64,
                updated_at_epoch_secs: now_epoch_secs(),
                cooldown_until_epoch_secs: cooldown_secs
                    .map(|secs| now_epoch_secs().saturating_add(secs)),
            },
        );
        let snapshot = guard.clone();
        drop(guard);

        write_rdap_rate_limit_cache(&self.throttle_cache_path, &snapshot);
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
            return CheckResult::rate_limited("RDAP circuit breaker open")
                .with_trace("RDAP: circuit breaker open");
        }

        if !domain.contains('.') {
            return CheckResult::error("Invalid domain").with_trace("RDAP: invalid domain");
        }

        let Some((_suffix, endpoint)) = self.endpoint_for_domain(domain) else {
            return CheckResult::available().with_trace("RDAP: unsupported suffix");
        };

        self.wait_for_turn(&endpoint).await;

        let url = format!("{}domain/{}", ensure_trailing_slash(&endpoint), domain);
        let response = match RDAP_CLIENT
            .get(&url)
            .header("Accept", "application/rdap+json, application/json")
            .send()
            .await
        {
            Ok(response) => response,
            Err(err) => {
                self.cb.record_failure();
                if err.is_timeout() {
                    let retry_after = self.record_transient_failure(&endpoint, None).await;
                    return CheckResult::retryable_error(
                        format!("RDAP request timeout: {}", err),
                        Some(retry_after.as_secs().max(1)),
                    )
                    .with_trace(format!("RDAP: timeout via {}", endpoint));
                }
                return CheckResult::retryable_error(
                    format!("RDAP request failed: {}", err),
                    Some(30),
                )
                .with_trace(format!("RDAP: request error via {}", endpoint));
            }
        };

        let retry_after = retry_after_from_headers(response.headers());
        match response.status() {
            reqwest::StatusCode::OK => {
                self.cb.record_success();
                self.record_success(&endpoint).await;
                match response.json::<RdapDomainResponse>().await {
                    Ok(payload) => CheckResult::registered_with_expiry(
                        vec!["RDAP".to_string()],
                        Self::extract_expiry(&payload),
                    )
                    .with_trace(format!("RDAP: registered via {}", endpoint)),
                    Err(err) => CheckResult::error(format!("RDAP parse failed: {}", err))
                        .with_trace(format!("RDAP: parse failed via {}", endpoint)),
                }
            }
            reqwest::StatusCode::NOT_FOUND => {
                self.cb.record_success();
                self.record_success(&endpoint).await;
                CheckResult::available().with_trace(format!("RDAP: not found via {}", endpoint))
            }
            reqwest::StatusCode::TOO_MANY_REQUESTS => {
                self.cb.record_failure();
                let retry_after = self.record_rate_limit(&endpoint, retry_after).await;
                CheckResult::rate_limited_with_retry(
                    "RDAP rate limit exceeded (HTTP 429)",
                    Some(retry_after.as_secs().max(1)),
                )
                .with_trace(format!("RDAP: HTTP 429 via {}", endpoint))
            }
            reqwest::StatusCode::FORBIDDEN => {
                self.cb.record_failure();
                let body = response.text().await.unwrap_or_default();
                if retry_after.is_none() && !looks_like_rdap_access_limit(&body) {
                    return CheckResult::error("RDAP access denied (HTTP 403)")
                        .with_trace(format!("RDAP: HTTP 403 via {}", endpoint));
                }
                let retry_after = self.record_rate_limit(&endpoint, retry_after).await;
                CheckResult::rate_limited_with_retry(
                    "RDAP access denied or rate limited (HTTP 403)",
                    Some(retry_after.as_secs().max(1)),
                )
                .with_trace(format!("RDAP: HTTP 403 via {}", endpoint))
            }
            status
                if status == reqwest::StatusCode::BAD_GATEWAY
                    || status == reqwest::StatusCode::SERVICE_UNAVAILABLE
                    || status == reqwest::StatusCode::GATEWAY_TIMEOUT =>
            {
                self.cb.record_failure();
                let retry_after = self.record_transient_failure(&endpoint, retry_after).await;
                CheckResult::retryable_error(
                    format!("RDAP returned transient HTTP {}", status),
                    Some(retry_after.as_secs().max(1)),
                )
                .with_trace(format!("RDAP: HTTP {} via {}", status, endpoint))
            }
            status => {
                self.cb.record_failure();
                CheckResult::error(format!("RDAP returned HTTP {}", status))
                    .with_trace(format!("RDAP: HTTP {} via {}", status, endpoint))
            }
        }
    }

    fn supports_tld(&self, tld: &str) -> bool {
        self.endpoint_map.contains_key(tld)
    }

    fn is_authoritative(&self) -> bool {
        true
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

fn looks_like_rdap_access_limit(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("rate")
        || lower.contains("limit")
        || lower.contains("quota")
        || lower.contains("too many")
        || lower.contains("temporar")
        || lower.contains("try again")
        || lower.contains("blocked")
        || lower.contains("blacklist")
}

fn normalize_endpoint_map(input: HashMap<String, String>) -> HashMap<String, String> {
    let mut normalized = HashMap::new();
    for (suffix, endpoint) in input {
        let suffix = suffix.trim().trim_start_matches('.').to_ascii_lowercase();
        let endpoint = endpoint.trim().to_string();
        if !suffix.is_empty() && !endpoint.is_empty() {
            normalized.insert(suffix, endpoint);
        }
    }
    normalized
}

fn builtin_endpoint_map() -> HashMap<String, String> {
    BUILTIN_RDAP_ENDPOINTS
        .iter()
        .map(|(suffix, endpoint)| (suffix.to_string(), endpoint.to_string()))
        .collect()
}

fn ensure_trailing_slash(endpoint: &str) -> String {
    if endpoint.ends_with('/') {
        endpoint.to_string()
    } else {
        format!("{}/", endpoint)
    }
}

async fn fetch_bootstrap_map(url: &str) -> Result<HashMap<String, String>, String> {
    let response = RDAP_CLIENT
        .get(url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|err| err.to_string())?;

    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()));
    }

    let document = response
        .json::<BootstrapDocument>()
        .await
        .map_err(|err| err.to_string())?;

    let mut endpoint_map = HashMap::new();
    for (suffixes, endpoints) in document.services {
        let Some(endpoint) = endpoints.into_iter().next() else {
            continue;
        };
        let endpoint = endpoint.trim().to_string();
        if endpoint.is_empty() {
            continue;
        }
        for suffix in suffixes {
            let suffix = suffix.trim().trim_start_matches('.').to_ascii_lowercase();
            if !suffix.is_empty() {
                endpoint_map.insert(suffix, endpoint.clone());
            }
        }
    }

    Ok(endpoint_map)
}

async fn fetch_bootstrap_map_with_cache(
    url: &str,
    cache_dir: Option<&Path>,
) -> Result<HashMap<String, String>, String> {
    let cache_path = cache_file_path(url, cache_dir)?;
    if let Some(cache) = read_cache_file(&cache_path) {
        if cache.source_url == url && is_cache_fresh(cache.fetched_at_epoch_secs) {
            debug!(
                target: "domain_scanner::checker::rdap",
                context = "bootstrap_cache",
                path = %cache_path.display(),
                "RDAP bootstrap cache hit"
            );
            return Ok(cache.endpoint_map);
        }
        debug!(
            target: "domain_scanner::checker::rdap",
            context = "bootstrap_cache",
            path = %cache_path.display(),
            "RDAP bootstrap cache stale"
        );
    }

    match fetch_bootstrap_map(url).await {
        Ok(endpoint_map) => {
            info!(
                target: "domain_scanner::checker::rdap",
                context = "bootstrap_cache",
                source = %url,
                path = %cache_path.display(),
                mappings = endpoint_map.len(),
                "RDAP bootstrap cache refreshed"
            );
            write_cache_file(
                &cache_path,
                &BootstrapCacheFile {
                    source_url: url.to_string(),
                    fetched_at_epoch_secs: now_epoch_secs(),
                    endpoint_map: endpoint_map.clone(),
                },
            );
            Ok(endpoint_map)
        }
        Err(fetch_err) => {
            if let Some(cache) = read_cache_file(&cache_path) {
                if cache.source_url == url {
                    warn!(
                        target: "domain_scanner::checker::rdap",
                        context = "bootstrap_cache",
                        source = %url,
                        error = %fetch_err,
                        "failed to refresh RDAP bootstrap; using cached data"
                    );
                    return Ok(cache.endpoint_map);
                }
            }
            warn!(
                target: "domain_scanner::checker::rdap",
                context = "bootstrap_cache",
                source = %url,
                error = %fetch_err,
                "RDAP bootstrap unavailable and no cache fallback"
            );
            Err(fetch_err)
        }
    }
}

fn cache_file_path(url: &str, cache_dir: Option<&Path>) -> Result<PathBuf, String> {
    let base_dir = cache_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(default_cache_dir);
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    url.hash(&mut hasher);
    let filename = format!("{:016x}.json", hasher.finish());
    Ok(base_dir.join(filename))
}

fn default_cache_dir() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("data")
        .join("cache")
        .join("rdap")
}

fn default_rdap_rate_limit_cache_path() -> PathBuf {
    default_cache_dir().join("rate_limits.json")
}

fn load_cached_rdap_throttles(
    cache_path: &Path,
) -> (
    HashMap<String, RdapRateLimitCacheEntry>,
    HashMap<String, Arc<Mutex<RdapEndpointThrottle>>>,
) {
    let cache_entries = read_rdap_rate_limit_cache(cache_path);
    let throttles = cache_entries
        .iter()
        .map(|(endpoint, entry)| {
            (
                endpoint.clone(),
                Arc::new(Mutex::new(RdapEndpointThrottle::from_cache(entry))),
            )
        })
        .collect();
    (cache_entries, throttles)
}

fn read_rdap_rate_limit_cache(path: &Path) -> HashMap<String, RdapRateLimitCacheEntry> {
    let Ok(content) = fs::read_to_string(path) else {
        return HashMap::new();
    };

    match serde_json::from_str::<RdapRateLimitCacheFile>(&content) {
        Ok(cache) => cache
            .endpoints
            .into_iter()
            .filter(|(_, entry)| entry.min_interval_ms > 0)
            .collect(),
        Err(err) => {
            warn!(
                target: "domain_scanner::checker::rdap",
                context = "rate_limit_cache",
                path = %path.display(),
                error = %err,
                "failed to parse RDAP rate-limit cache"
            );
            HashMap::new()
        }
    }
}

fn write_rdap_rate_limit_cache(path: &Path, endpoints: &HashMap<String, RdapRateLimitCacheEntry>) {
    let Some(parent) = path.parent() else {
        return;
    };

    if let Err(err) = fs::create_dir_all(parent) {
        warn!(
            target: "domain_scanner::checker::rdap",
            context = "rate_limit_cache",
            path = %parent.display(),
            error = %err,
            "failed to create RDAP rate-limit cache directory"
        );
        return;
    }

    let serialized = match serde_json::to_vec_pretty(&RdapRateLimitCacheFile {
        endpoints: endpoints.clone(),
    }) {
        Ok(serialized) => serialized,
        Err(err) => {
            warn!(
                target: "domain_scanner::checker::rdap",
                context = "rate_limit_cache",
                path = %path.display(),
                error = %err,
                "failed to serialize RDAP rate-limit cache"
            );
            return;
        }
    };

    if let Err(err) = fs::write(path, serialized) {
        warn!(
            target: "domain_scanner::checker::rdap",
            context = "rate_limit_cache",
            path = %path.display(),
            error = %err,
            "failed to write RDAP rate-limit cache"
        );
    }
}

fn read_cache_file(path: &Path) -> Option<BootstrapCacheFile> {
    let content = fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

fn write_cache_file(path: &Path, cache: &BootstrapCacheFile) {
    let Some(parent) = path.parent() else {
        return;
    };
    if let Err(err) = fs::create_dir_all(parent) {
        warn!(
            target: "domain_scanner::checker::rdap",
            context = "bootstrap_cache",
            path = %parent.display(),
            error = %err,
            "failed to create RDAP cache directory"
        );
        return;
    }

    let serialized = match serde_json::to_vec(cache) {
        Ok(serialized) => serialized,
        Err(err) => {
            warn!(
                target: "domain_scanner::checker::rdap",
                context = "bootstrap_cache",
                path = %path.display(),
                error = %err,
                "failed to serialize RDAP cache"
            );
            return;
        }
    };

    if let Err(err) = fs::write(path, serialized) {
        warn!(
            target: "domain_scanner::checker::rdap",
            context = "bootstrap_cache",
            path = %path.display(),
            error = %err,
            "failed to write RDAP cache"
        );
    }
}

fn is_cache_fresh(fetched_at_epoch_secs: u64) -> bool {
    now_epoch_secs().saturating_sub(fetched_at_epoch_secs) <= RDAP_BOOTSTRAP_CACHE_TTL_SECS
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
    use reqwest::header::{HeaderValue, RETRY_AFTER};

    #[test]
    fn test_retry_after_from_headers_parses_seconds() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("90"));

        assert_eq!(
            retry_after_from_headers(&headers),
            Some(Duration::from_secs(90))
        );
    }

    #[test]
    fn test_retry_after_from_headers_parses_http_date() {
        let mut headers = HeaderMap::new();
        let future = chrono::Utc::now() + chrono::Duration::seconds(60);
        headers.insert(
            RETRY_AFTER,
            HeaderValue::from_str(&future.to_rfc2822()).unwrap(),
        );

        let parsed = retry_after_from_headers(&headers).unwrap();
        assert!(parsed.as_secs() >= 1);
        assert!(parsed.as_secs() <= 120);
    }
}
