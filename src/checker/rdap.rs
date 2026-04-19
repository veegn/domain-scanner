use std::collections::HashMap;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

use super::circuit_breaker::CircuitBreaker;
use super::traits::{CheckResult, CheckerPriority, DomainChecker};

static RDAP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .user_agent("domain-scanner/0.1")
        .build()
        .unwrap()
});

const RDAP_BOOTSTRAP_CACHE_TTL_SECS: u64 = 24 * 60 * 60;

#[derive(Debug, Clone)]
pub struct RdapChecker {
    endpoint_map: Arc<HashMap<String, String>>,
    cb: Arc<CircuitBreaker>,
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
        let mut endpoint_map = normalize_endpoint_map(custom_endpoints);

        if let Some(url) = bootstrap_url.filter(|url| !url.trim().is_empty()) {
            match fetch_bootstrap_map_with_cache(&url, cache_dir.as_deref()).await {
                Ok(bootstrap_endpoints) => {
                    println!(
                        "RDAP bootstrap loaded from {} with {} suffix mappings",
                        url,
                        bootstrap_endpoints.len()
                    );
                    for (suffix, endpoint) in bootstrap_endpoints {
                        endpoint_map.entry(suffix).or_insert(endpoint);
                    }
                }
                Err(err) => {
                    eprintln!("Warning: Failed to load RDAP bootstrap {}: {}", url, err);
                }
            }
        }

        Self {
            endpoint_map: Arc::new(endpoint_map),
            cb: Arc::new(CircuitBreaker::new(10, 60)),
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
                return CheckResult::error(format!("RDAP request failed: {}", err))
                    .with_trace(format!("RDAP: request error via {}", endpoint));
            }
        };

        match response.status() {
            reqwest::StatusCode::OK => {
                self.cb.record_success();
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
                CheckResult::available().with_trace(format!("RDAP: not found via {}", endpoint))
            }
            reqwest::StatusCode::TOO_MANY_REQUESTS => {
                self.cb.record_failure();
                CheckResult::rate_limited("RDAP rate limit exceeded (HTTP 429)")
                    .with_trace(format!("RDAP: HTTP 429 via {}", endpoint))
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
            println!("RDAP bootstrap cache hit: {:?}", cache_path);
            return Ok(cache.endpoint_map);
        }
        println!("RDAP bootstrap cache stale: {:?}", cache_path);
    }

    match fetch_bootstrap_map(url).await {
        Ok(endpoint_map) => {
            println!(
                "RDAP bootstrap refreshed from remote {} into cache {:?}",
                url, cache_path
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
                    eprintln!(
                        "Warning: Failed to refresh RDAP bootstrap {}; using cached data: {}",
                        url, fetch_err
                    );
                    return Ok(cache.endpoint_map);
                }
            }
            eprintln!(
                "Warning: RDAP bootstrap unavailable and no cache fallback for {}: {}",
                url, fetch_err
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

fn read_cache_file(path: &Path) -> Option<BootstrapCacheFile> {
    let content = fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

fn write_cache_file(path: &Path, cache: &BootstrapCacheFile) {
    let Some(parent) = path.parent() else {
        return;
    };
    if let Err(err) = fs::create_dir_all(parent) {
        eprintln!(
            "Warning: Failed to create RDAP cache dir {:?}: {}",
            parent, err
        );
        return;
    }

    let serialized = match serde_json::to_vec(cache) {
        Ok(serialized) => serialized,
        Err(err) => {
            eprintln!(
                "Warning: Failed to serialize RDAP cache {:?}: {}",
                path, err
            );
            return;
        }
    };

    if let Err(err) = fs::write(path, serialized) {
        eprintln!("Warning: Failed to write RDAP cache {:?}: {}", path, err);
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
