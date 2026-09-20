//! DNSHE provider WHOIS checker.
//!
//! DNSHE operates registrations below a set of shared two-label suffixes. Those
//! child registrations are not represented by the parent registry's RDAP or
//! port-43 WHOIS data, so supported descendants use this checker exclusively.

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue, RETRY_AFTER};
use reqwest::{StatusCode, Url};
use serde::Deserialize;
use sqlx::SqlitePool;
use std::env;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tracing::{debug, warn};

use super::traits::{
    CheckResult, CheckerPriority, DomainChecker, acquire_network_permit, retry_delay_secs,
};

const DNSHE_API_ENDPOINT: &str = "https://api005.dnshe.com/index.php?m=domain_hub";
const DNSHE_API_KEY_ENV: &str = "DNSHE_API_KEY";
const DNSHE_API_SECRET_ENV: &str = "DNSHE_API_SECRET";
const DNSHE_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const DNSHE_TRANSIENT_BACKOFF: Duration = Duration::from_secs(30);
const DNSHE_RATE_LIMIT_BACKOFF: Duration = Duration::from_secs(60);
const DNSHE_RATE_STORAGE_BACKOFF: Duration = Duration::from_secs(5);
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_RETRY_AFTER: Duration = Duration::from_secs(24 * 60 * 60);
const DNSHE_RATE_LIMIT_SCOPE: &str = "dnshe-whois";

pub(crate) const DNSHE_RATE_LIMIT_SCHEMA_SQL: &str = "CREATE TABLE IF NOT EXISTS api_rate_limits (
        scope TEXT PRIMARY KEY,
        next_allowed_at_ms INTEGER NOT NULL,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    )";

/// A 2001 ms interval keeps millisecond timestamps from admitting a boundary
/// request early and guarantees at most 30 starts in any rolling 60 seconds.
/// The value is intentionally not configurable.
pub const DNSHE_REQUESTS_PER_MINUTE: u32 = 30;
pub const DNSHE_MIN_REQUEST_INTERVAL: Duration = Duration::from_millis(2001);

pub const DNSHE_SUPPORTED_SUFFIXES: &[&str] = &[
    "l.cd",
    "us.ci",
    "bot.cd",
    "de5.net",
    "ccwu.cc",
    "ddns.ge",
    "bbroot.com",
];

#[derive(Clone)]
struct DnsheCredentials {
    api_key: HeaderValue,
    api_secret: HeaderValue,
}

impl fmt::Debug for DnsheCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DnsheCredentials([REDACTED])")
    }
}

impl DnsheCredentials {
    fn from_environment() -> Result<Self, &'static str> {
        let key = read_environment_secret(DNSHE_API_KEY_ENV)?;
        let secret = read_environment_secret(DNSHE_API_SECRET_ENV)?;
        Self::from_strings(&key, &secret)
    }

    fn from_strings(api_key: &str, api_secret: &str) -> Result<Self, &'static str> {
        let mut api_key = HeaderValue::from_str(api_key.trim())
            .map_err(|_| "DNSHE API credentials contain invalid header characters")?;
        let mut api_secret = HeaderValue::from_str(api_secret.trim())
            .map_err(|_| "DNSHE API credentials contain invalid header characters")?;
        if api_key.is_empty() || api_secret.is_empty() {
            return Err("DNSHE_API_KEY and DNSHE_API_SECRET must both be configured");
        }
        api_key.set_sensitive(true);
        api_secret.set_sensitive(true);
        Ok(Self {
            api_key,
            api_secret,
        })
    }
}

fn read_environment_secret(name: &str) -> Result<String, &'static str> {
    let value =
        env::var_os(name).ok_or("DNSHE_API_KEY and DNSHE_API_SECRET must both be configured")?;
    let value = value
        .into_string()
        .map_err(|_| "DNSHE API credentials must be valid Unicode")?;
    if value.trim().is_empty() {
        return Err("DNSHE_API_KEY and DNSHE_API_SECRET must both be configured");
    }
    Ok(value)
}

#[derive(Debug)]
struct DnsheRateState {
    next_allowed_at: Instant,
}

#[derive(Debug)]
struct DnsheRateGate {
    min_interval: Duration,
    state: Mutex<DnsheRateState>,
    persistence: Option<SqlitePool>,
}

#[derive(Debug)]
enum DnsheRateGateError {
    Deferred(Duration),
    StorageUnavailable,
}

impl DnsheRateGate {
    #[cfg(test)]
    fn new(min_interval: Duration) -> Self {
        Self {
            min_interval,
            state: Mutex::new(DnsheRateState {
                next_allowed_at: Instant::now(),
            }),
            persistence: None,
        }
    }

    fn with_persistence(min_interval: Duration, persistence: SqlitePool) -> Self {
        Self {
            min_interval,
            state: Mutex::new(DnsheRateState {
                next_allowed_at: Instant::now(),
            }),
            persistence: Some(persistence),
        }
    }

    async fn try_claim(&self) -> Result<(), DnsheRateGateError> {
        let mut state = self.state.lock().await;
        let now = Instant::now();
        if now < state.next_allowed_at {
            return Err(DnsheRateGateError::Deferred(
                state.next_allowed_at.saturating_duration_since(now),
            ));
        }
        if let Some(pool) = &self.persistence {
            match claim_persisted_rate_slot(pool, self.min_interval).await {
                Ok(Some(delay)) => {
                    state.next_allowed_at = Instant::now() + delay;
                    return Err(DnsheRateGateError::Deferred(delay));
                }
                Ok(None) => {}
                Err(error) => {
                    state.next_allowed_at = Instant::now() + DNSHE_RATE_STORAGE_BACKOFF;
                    warn!(
                        target: "domain_scanner::checker::dnshe",
                        context = "rate_limit_storage",
                        error = %error,
                        "DNSHE rate-limit claim failed closed"
                    );
                    return Err(DnsheRateGateError::StorageUnavailable);
                }
            }
        }
        state.next_allowed_at = Instant::now() + self.min_interval;
        Ok(())
    }

    async fn block_for(&self, delay: Duration) {
        let delay = delay.min(MAX_RETRY_AFTER);
        let blocked_until = Instant::now() + delay;
        let mut state = self.state.lock().await;
        state.next_allowed_at = state.next_allowed_at.max(blocked_until);
        if let Some(pool) = &self.persistence
            && let Err(error) = extend_persisted_rate_block(pool, delay).await
        {
            warn!(
                target: "domain_scanner::checker::dnshe",
                context = "rate_limit_storage",
                error = %error,
                "could not persist DNSHE provider cooldown"
            );
        }
    }
}

async fn claim_persisted_rate_slot(
    pool: &SqlitePool,
    min_interval: Duration,
) -> Result<Option<Duration>, sqlx::Error> {
    // Acquire SQLite's write reservation before reading wall time. Otherwise a
    // busy wait could make the proposed next slot stale before it is written.
    let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await?;
    let now_ms = unix_epoch_millis();
    let next_allowed_at_ms = now_ms.saturating_add(duration_millis(min_interval));
    let claimed = sqlx::query_scalar::<_, i64>(
        "INSERT INTO api_rate_limits (scope, next_allowed_at_ms, updated_at)
         VALUES (?1, ?2, CURRENT_TIMESTAMP)
         ON CONFLICT(scope) DO UPDATE SET
             next_allowed_at_ms = excluded.next_allowed_at_ms,
             updated_at = CURRENT_TIMESTAMP
         WHERE api_rate_limits.next_allowed_at_ms <= ?3
         RETURNING next_allowed_at_ms",
    )
    .bind(DNSHE_RATE_LIMIT_SCOPE)
    .bind(next_allowed_at_ms)
    .bind(now_ms)
    .fetch_optional(&mut *transaction)
    .await?;
    if claimed.is_some() {
        transaction.commit().await?;
        return Ok(None);
    }

    let stored_next_ms = sqlx::query_scalar::<_, i64>(
        "SELECT next_allowed_at_ms FROM api_rate_limits WHERE scope = ?1",
    )
    .bind(DNSHE_RATE_LIMIT_SCOPE)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    let remaining_ms = stored_next_ms
        .saturating_sub(unix_epoch_millis())
        .max(1)
        .min(duration_millis(MAX_RETRY_AFTER));
    Ok(Some(Duration::from_millis(remaining_ms as u64)))
}

async fn extend_persisted_rate_block(
    pool: &SqlitePool,
    delay: Duration,
) -> Result<(), sqlx::Error> {
    let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await?;
    let blocked_until_ms = unix_epoch_millis().saturating_add(duration_millis(delay));
    sqlx::query(
        "INSERT INTO api_rate_limits (scope, next_allowed_at_ms, updated_at)
         VALUES (?1, ?2, CURRENT_TIMESTAMP)
         ON CONFLICT(scope) DO UPDATE SET
             next_allowed_at_ms = MAX(api_rate_limits.next_allowed_at_ms, excluded.next_allowed_at_ms),
             updated_at = CURRENT_TIMESTAMP",
    )
    .bind(DNSHE_RATE_LIMIT_SCOPE)
    .bind(blocked_until_ms)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

fn unix_epoch_millis() -> i64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    millis.min(i64::MAX as u128) as i64
}

fn duration_millis(duration: Duration) -> i64 {
    duration.as_millis().max(1).min(i64::MAX as u128) as i64
}

#[derive(Debug, Deserialize)]
struct DnsheWhoisResponse {
    #[serde(default)]
    success: bool,
    domain: Option<String>,
    source_type: Option<String>,
    registered: Option<bool>,
    status: Option<String>,
    expires_at: Option<String>,
    root_domain: Option<String>,
    error_code: Option<String>,
}

/// Authoritative checker for DNSHE-managed third-level registrations.
pub struct DnsheChecker {
    client: reqwest::Client,
    endpoint: Url,
    credentials: Option<DnsheCredentials>,
    configuration_error: Option<&'static str>,
    authentication_rejected: AtomicBool,
    rate_gate: Arc<DnsheRateGate>,
}

impl fmt::Debug for DnsheChecker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsheChecker")
            .field("endpoint", &self.endpoint)
            .field("credentials_configured", &self.credentials.is_some())
            .field("requests_per_minute", &DNSHE_REQUESTS_PER_MINUTE)
            .finish()
    }
}

impl DnsheChecker {
    /// Build the production checker with a SQLite-backed gate. All application
    /// instances that share this database also share the same request slot.
    pub fn from_env_with_db(db: SqlitePool) -> Self {
        Self::from_env_with_gate(Arc::new(DnsheRateGate::with_persistence(
            DNSHE_MIN_REQUEST_INTERVAL,
            db,
        )))
    }

    fn from_env_with_gate(rate_gate: Arc<DnsheRateGate>) -> Self {
        let (credentials, configuration_error) = match DnsheCredentials::from_environment() {
            Ok(credentials) => (Some(credentials), None),
            Err(error) => {
                warn!(
                    target: "domain_scanner::checker::dnshe",
                    context = "configuration",
                    error,
                    "DNSHE checker credentials are not available"
                );
                (None, Some(error))
            }
        };
        Self::build(
            Url::parse(DNSHE_API_ENDPOINT).expect("DNSHE API endpoint must be a valid URL"),
            credentials,
            configuration_error,
            rate_gate,
        )
    }

    fn build(
        endpoint: Url,
        credentials: Option<DnsheCredentials>,
        configuration_error: Option<&'static str>,
        rate_gate: Arc<DnsheRateGate>,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(DNSHE_REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("domain-scanner/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("DNSHE HTTP client must build");
        Self {
            client,
            endpoint,
            credentials,
            configuration_error,
            authentication_rejected: AtomicBool::new(false),
            rate_gate,
        }
    }

    #[cfg(test)]
    fn for_test(endpoint: Url, min_interval: Duration) -> Self {
        Self::build(
            endpoint,
            Some(DnsheCredentials::from_strings("test-key", "test-secret").unwrap()),
            None,
            Arc::new(DnsheRateGate::new(min_interval)),
        )
    }

    #[cfg(test)]
    fn for_test_with_db(endpoint: Url, min_interval: Duration, db: SqlitePool) -> Self {
        Self::build(
            endpoint,
            Some(DnsheCredentials::from_strings("test-key", "test-secret").unwrap()),
            None,
            Arc::new(DnsheRateGate::with_persistence(min_interval, db)),
        )
    }

    fn request_url(&self, domain: &str) -> Url {
        let mut url = self.endpoint.clone();
        url.query_pairs_mut()
            .append_pair("endpoint", "whois")
            .append_pair("domain", domain);
        url
    }

    async fn decode_success_response(
        mut response: reqwest::Response,
    ) -> Result<DnsheWhoisResponse, &'static str> {
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "DNSHE response body could not be read")?
        {
            if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err("DNSHE response exceeded the size limit");
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|_| "DNSHE response was not valid JSON")
    }

    async fn classify_payload(
        &self,
        requested_domain: &str,
        requested_suffix: &str,
        payload: DnsheWhoisResponse,
        retry_after: Option<Duration>,
    ) -> CheckResult {
        if !payload.success {
            let error_code = payload.error_code.as_deref().unwrap_or("unknown_error");
            if matches!(error_code, "rate_limit_exceeded" | "quota_exceeded") {
                let delay = retry_after.unwrap_or(DNSHE_RATE_LIMIT_BACKOFF);
                self.rate_gate.block_for(delay).await;
                return CheckResult::rate_limited_with_retry(
                    "DNSHE API rate limit exceeded",
                    Some(retry_delay_secs(delay)),
                )
                .with_trace("DNSHE: provider reported a rate limit");
            }
            if matches!(
                error_code,
                "auth_invalid_credentials" | "auth_ip_not_allowed" | "api_access_disabled"
            ) {
                self.authentication_rejected.store(true, Ordering::Release);
                return CheckResult::error("DNSHE API authentication or access was rejected")
                    .with_trace("DNSHE: authentication or access rejected");
            }
            return CheckResult::error(format!("DNSHE API returned error code {error_code}"))
                .with_trace("DNSHE: unsuccessful JSON response");
        }

        let Some(response_domain) = payload.domain.as_deref() else {
            return CheckResult::error("DNSHE response omitted the requested domain")
                .with_trace("DNSHE: response identity missing");
        };
        if normalize_domain(response_domain) != requested_domain {
            return CheckResult::error("DNSHE response domain did not match the request")
                .with_trace("DNSHE: response domain mismatch");
        }
        if !payload
            .source_type
            .as_deref()
            .is_some_and(|source| source.eq_ignore_ascii_case("internal"))
        {
            return CheckResult::error("DNSHE response was not from the internal registry")
                .with_trace("DNSHE: external or missing response source");
        }
        if let Some(root_domain) = payload
            .root_domain
            .as_deref()
            .filter(|root| !root.trim().is_empty())
            && normalize_domain(root_domain) != requested_suffix
        {
            return CheckResult::error("DNSHE response root domain did not match the request")
                .with_trace("DNSHE: response root-domain mismatch");
        }

        match payload.registered {
            Some(true)
                if payload
                    .status
                    .as_deref()
                    .is_some_and(|status| status.eq_ignore_ascii_case("unregistered")) =>
            {
                CheckResult::error("DNSHE response contained an inconsistent registration state")
                    .with_trace("DNSHE: inconsistent registration state")
            }
            Some(true) => {
                let expiration = payload
                    .expires_at
                    .map(|value| value.trim().to_string())
                    .filter(|value| !value.is_empty());
                CheckResult::registered_with_expiry(vec!["DNSHE".to_string()], expiration)
                    .with_trace("DNSHE: internal registration record found")
            }
            Some(false)
                if payload
                    .status
                    .as_deref()
                    .is_some_and(|status| status.eq_ignore_ascii_case("unregistered")) =>
            {
                CheckResult::no_registration_record()
                    .with_trace("DNSHE: internal registry reported no registration record")
            }
            _ => CheckResult::error("DNSHE response contained an inconsistent registration state")
                .with_trace("DNSHE: inconsistent registration state"),
        }
    }
}

#[async_trait]
impl DomainChecker for DnsheChecker {
    fn name(&self) -> &'static str {
        "DNSHE"
    }

    fn priority(&self) -> CheckerPriority {
        CheckerPriority::Provider
    }

    async fn check(&self, domain: &str) -> CheckResult {
        let normalized = normalize_domain(domain);
        let Some(suffix) = managed_suffix(&normalized) else {
            return CheckResult::error("DNSHE does not manage this domain suffix")
                .with_trace("DNSHE: unsupported suffix");
        };
        if !is_exact_third_level_domain(&normalized, suffix) {
            return CheckResult::error(
                "DNSHE scans require exactly one label before the managed suffix",
            )
            .with_trace("DNSHE: invalid managed-domain depth or label");
        }

        let Some(credentials) = self.credentials.as_ref() else {
            return CheckResult::error(
                self.configuration_error
                    .unwrap_or("DNSHE API credentials are not configured"),
            )
            .with_trace("DNSHE: credentials unavailable");
        };
        if self.authentication_rejected.load(Ordering::Acquire) {
            return CheckResult::error(
                "DNSHE API authentication was previously rejected; restart after replacing credentials",
            )
            .with_trace("DNSHE: authentication disabled after provider rejection");
        }

        let _permit = match acquire_network_permit() {
            Ok(permit) => permit,
            Err(_) => {
                return CheckResult::deferred(
                    "global network limiter busy",
                    Duration::from_secs(1),
                )
                .with_trace("DNSHE: global network limiter busy");
            }
        };
        match self.rate_gate.try_claim().await {
            Ok(()) => {}
            Err(DnsheRateGateError::Deferred(delay)) => {
                return CheckResult::deferred("DNSHE fixed 30 requests/minute limit", delay)
                    .with_trace("DNSHE: deferred by shared 30 requests/minute limiter");
            }
            Err(DnsheRateGateError::StorageUnavailable) => {
                return CheckResult::deferred(
                    "DNSHE rate-limit storage is unavailable",
                    DNSHE_RATE_STORAGE_BACKOFF,
                )
                .with_trace("DNSHE: persistent rate limiter unavailable; request blocked");
            }
        }

        let response = match self
            .client
            .get(self.request_url(&normalized))
            .header("X-API-Key", credentials.api_key.clone())
            .header("X-API-Secret", credentials.api_secret.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                self.rate_gate.block_for(DNSHE_TRANSIENT_BACKOFF).await;
                debug!(
                    target: "domain_scanner::checker::dnshe",
                    context = "request",
                    domain = normalized,
                    error = %error,
                    "DNSHE request failed"
                );
                return CheckResult::retryable_error(
                    "DNSHE API request failed",
                    Some(DNSHE_TRANSIENT_BACKOFF.as_secs()),
                )
                .with_trace("DNSHE: request failed");
            }
        };

        let status = response.status();
        let retry_after = retry_after_from_headers(response.headers());
        if status == StatusCode::TOO_MANY_REQUESTS {
            let delay = retry_after.unwrap_or(DNSHE_RATE_LIMIT_BACKOFF);
            self.rate_gate.block_for(delay).await;
            return CheckResult::rate_limited_with_retry(
                "DNSHE API rate limit exceeded (HTTP 429)",
                Some(retry_delay_secs(delay)),
            )
            .with_trace("DNSHE: HTTP 429 rate limit");
        }
        if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
            self.authentication_rejected.store(true, Ordering::Release);
            return CheckResult::error("DNSHE API authentication or access was rejected")
                .with_trace(format!("DNSHE: HTTP {status} authentication failure"));
        }
        if status == StatusCode::REQUEST_TIMEOUT || status.is_server_error() {
            let delay = retry_after.unwrap_or(DNSHE_TRANSIENT_BACKOFF);
            self.rate_gate.block_for(delay).await;
            return CheckResult::retryable_error(
                format!("DNSHE API returned transient HTTP {status}"),
                Some(retry_delay_secs(delay)),
            )
            .with_trace(format!("DNSHE: transient HTTP {status}"));
        }
        if !status.is_success() {
            return CheckResult::error(format!("DNSHE API returned HTTP {status}"))
                .with_trace(format!("DNSHE: terminal HTTP {status}"));
        }

        let payload = match Self::decode_success_response(response).await {
            Ok(payload) => payload,
            Err(error) => {
                self.rate_gate.block_for(DNSHE_TRANSIENT_BACKOFF).await;
                return CheckResult::retryable_error(
                    error,
                    Some(DNSHE_TRANSIENT_BACKOFF.as_secs()),
                )
                .with_trace("DNSHE: response decoding failed");
            }
        };
        self.classify_payload(&normalized, suffix, payload, retry_after)
            .await
    }

    fn supports_tld(&self, tld: &str) -> bool {
        let normalized = tld.trim().trim_start_matches('.').to_ascii_lowercase();
        DNSHE_SUPPORTED_SUFFIXES.contains(&normalized.as_str())
    }

    fn supports_domain(&self, domain: &str) -> bool {
        managed_suffix(&normalize_domain(domain)).is_some()
    }

    fn exclusive_for_domain(&self, domain: &str) -> bool {
        self.supports_domain(domain)
    }

    fn is_authoritative(&self) -> bool {
        true
    }

    fn should_stop_pipeline(&self, result: &CheckResult) -> bool {
        result.registration_record_absent || result.has_registration_evidence()
    }
}

fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn managed_suffix(domain: &str) -> Option<&'static str> {
    DNSHE_SUPPORTED_SUFFIXES.iter().copied().find(|suffix| {
        domain
            .strip_suffix(suffix)
            .and_then(|prefix| prefix.strip_suffix('.'))
            .is_some_and(|prefix| !prefix.is_empty())
    })
}

fn is_exact_third_level_domain(domain: &str, suffix: &str) -> bool {
    if domain.len() > 253 {
        return false;
    }
    let Some(prefix) = domain
        .strip_suffix(suffix)
        .and_then(|prefix| prefix.strip_suffix('.'))
    else {
        return false;
    };
    !prefix.contains('.') && is_valid_dns_label(prefix)
}

fn is_valid_dns_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn retry_after_from_headers(headers: &HeaderMap) -> Option<Duration> {
    let raw = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
    if let Ok(seconds) = raw.parse::<u64>() {
        return Some(Duration::from_secs(seconds.max(1)).min(MAX_RETRY_AFTER));
    }
    let parsed = chrono::DateTime::parse_from_rfc2822(raw).ok()?;
    let seconds = parsed
        .with_timezone(&chrono::Utc)
        .signed_duration_since(chrono::Utc::now())
        .num_seconds();
    Some(Duration::from_secs(seconds.max(1) as u64).min(MAX_RETRY_AFTER))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Query, State};
    use axum::http::{HeaderMap as AxumHeaderMap, StatusCode as AxumStatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::routing::get;
    use axum::{Json, Router};
    use serde_json::json;
    use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool as StdAtomicBool, AtomicUsize};

    #[derive(Clone, Default)]
    struct MockState {
        hits: Arc<AtomicUsize>,
        credentials_seen: Arc<StdAtomicBool>,
        query_seen: Arc<StdAtomicBool>,
    }

    async fn mock_whois(
        State(state): State<MockState>,
        Query(query): Query<HashMap<String, String>>,
        headers: AxumHeaderMap,
    ) -> Response {
        state.hits.fetch_add(1, Ordering::SeqCst);
        state.credentials_seen.store(
            headers.get("x-api-key").and_then(|v| v.to_str().ok()) == Some("test-key")
                && headers.get("x-api-secret").and_then(|v| v.to_str().ok()) == Some("test-secret"),
            Ordering::SeqCst,
        );
        state.query_seen.store(
            query.get("m").map(String::as_str) == Some("domain_hub")
                && query.get("endpoint").map(String::as_str) == Some("whois"),
            Ordering::SeqCst,
        );

        let domain = query.get("domain").cloned().unwrap_or_default();
        if domain == "limited.us.ci" {
            return (
                AxumStatusCode::TOO_MANY_REQUESTS,
                [("retry-after", "7")],
                Json(json!({"success": false, "error_code": "rate_limit_exceeded"})),
            )
                .into_response();
        }
        if domain == "server-error.us.ci" {
            return (
                AxumStatusCode::BAD_GATEWAY,
                Json(json!({"success": false, "error_code": "provider_operation_failed"})),
            )
                .into_response();
        }
        if domain == "unauthorized.us.ci" {
            return (
                AxumStatusCode::UNAUTHORIZED,
                Json(json!({"success": false, "error_code": "auth_invalid_credentials"})),
            )
                .into_response();
        }
        if domain == "redirect.us.ci" {
            return (
                AxumStatusCode::FOUND,
                [(
                    "location",
                    "/index.php?m=domain_hub&endpoint=whois&domain=taken.us.ci",
                )],
            )
                .into_response();
        }
        if domain == "malformed.us.ci" {
            return (AxumStatusCode::OK, "not-json").into_response();
        }
        if domain == "mismatch.us.ci" {
            return Json(json!({
                "success": true,
                "domain": "other.us.ci",
                "source_type": "internal",
                "registered": false,
                "status": "unregistered",
                "root_domain": "us.ci"
            }))
            .into_response();
        }
        if domain == "external.us.ci" {
            return Json(json!({
                "success": true,
                "domain": domain,
                "source_type": "external",
                "registered": false,
                "status": "unregistered"
            }))
            .into_response();
        }
        if domain == "wrong-root.us.ci" {
            return Json(json!({
                "success": true,
                "domain": domain,
                "source_type": "internal",
                "registered": false,
                "status": "unregistered",
                "root_domain": "bot.cd"
            }))
            .into_response();
        }
        if domain == "contradictory.us.ci" {
            return Json(json!({
                "success": true,
                "domain": domain,
                "source_type": "internal",
                "registered": true,
                "status": "unregistered"
            }))
            .into_response();
        }
        if domain.starts_with("free.") {
            let suffix = managed_suffix(&domain).unwrap();
            return Json(json!({
                "success": true,
                "domain": domain,
                "source_type": "internal",
                "registered": false,
                "status": "unregistered",
                "root_domain": suffix,
                "registrant_email": "must-not-be-deserialized@example.test"
            }))
            .into_response();
        }
        Json(json!({
            "success": true,
            "domain": domain,
            "source_type": "internal",
            "registered": true,
            "status": "active",
            "expires_at": "2030-01-02 03:04:05",
            "registrant_email": "must-not-be-deserialized@example.test"
        }))
        .into_response()
    }

    async fn spawn_mock() -> (Url, MockState, tokio::task::JoinHandle<()>) {
        let state = MockState::default();
        let app = Router::new()
            .route("/index.php", get(mock_whois))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = Url::parse(&format!(
            "http://{}/index.php?m=domain_hub",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (endpoint, state, handle)
    }

    async fn persistent_rate_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(DNSHE_RATE_LIMIT_SCHEMA_SQL)
            .execute(&pool)
            .await
            .unwrap();
        pool
    }

    #[test]
    fn supports_only_dnshe_descendants_and_routes_invalid_depth_exclusively() {
        let checker = DnsheChecker::for_test(
            Url::parse("http://127.0.0.1:9/?m=domain_hub").unwrap(),
            Duration::ZERO,
        );
        for suffix in DNSHE_SUPPORTED_SUFFIXES {
            assert!(checker.supports_tld(suffix));
            assert!(checker.supports_domain(&format!("name.{suffix}")));
        }
        assert!(checker.supports_domain("a.b.us.ci"));
        assert!(checker.exclusive_for_domain("a.b.us.ci"));
        assert!(!checker.supports_domain("us.ci"));
        assert!(!checker.supports_domain("name.us.ci.example"));
        assert!(!checker.supports_domain("name.cc.cd"));
    }

    #[tokio::test]
    async fn maps_registered_and_unregistered_internal_responses() {
        let (endpoint, state, handle) = spawn_mock().await;
        let checker = DnsheChecker::for_test(endpoint, Duration::ZERO);

        let registered = checker.check("Taken.US.CI.").await;
        assert!(registered.error.is_none(), "{registered:?}");
        assert_eq!(registered.signatures, vec!["DNSHE"]);
        assert_eq!(
            registered.expiration_date.as_deref(),
            Some("2030-01-02 03:04:05")
        );

        let unregistered = checker.check("free.l.cd").await;
        assert!(unregistered.registration_record_absent, "{unregistered:?}");
        assert!(state.credentials_seen.load(Ordering::SeqCst));
        assert!(state.query_seen.load(Ordering::SeqCst));
        assert_eq!(state.hits.load(Ordering::SeqCst), 2);
        handle.abort();
    }

    #[tokio::test]
    async fn rejects_invalid_depth_and_untrusted_response_identity() {
        let (endpoint, state, handle) = spawn_mock().await;
        let checker = DnsheChecker::for_test(endpoint, Duration::ZERO);

        let deep = checker.check("a.b.us.ci").await;
        assert!(deep.error.is_some());
        assert_eq!(state.hits.load(Ordering::SeqCst), 0);

        let mismatch = checker.check("mismatch.us.ci").await;
        assert!(mismatch.error.is_some());
        assert!(!mismatch.registration_record_absent);

        let external = checker.check("external.us.ci").await;
        assert!(external.error.is_some());
        assert!(!external.registration_record_absent);

        let wrong_root = checker.check("wrong-root.us.ci").await;
        assert!(wrong_root.error.is_some());
        assert!(!wrong_root.registration_record_absent);

        let contradictory = checker.check("contradictory.us.ci").await;
        assert!(contradictory.error.is_some());
        assert!(!contradictory.registration_record_absent);

        let hits_before_redirect = state.hits.load(Ordering::SeqCst);
        let redirect = checker.check("redirect.us.ci").await;
        assert!(redirect.error.is_some());
        assert_eq!(
            state.hits.load(Ordering::SeqCst),
            hits_before_redirect + 1,
            "redirects must not trigger a second HTTP request"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn missing_credentials_and_malformed_json_never_become_no_record_results() {
        let (endpoint, state, handle) = spawn_mock().await;
        let missing = DnsheChecker::build(
            endpoint.clone(),
            None,
            Some("DNSHE credentials missing"),
            Arc::new(DnsheRateGate::new(Duration::ZERO)),
        );
        let missing_result = missing.check("free.us.ci").await;
        assert!(missing_result.error.is_some());
        assert!(!missing_result.registration_record_absent);
        assert_eq!(state.hits.load(Ordering::SeqCst), 0);

        let malformed = DnsheChecker::for_test(endpoint, Duration::ZERO)
            .check("malformed.us.ci")
            .await;
        assert!(malformed.retryable);
        assert!(!malformed.registration_record_absent);
        handle.abort();
    }

    #[tokio::test]
    async fn fixed_limiter_is_shared_across_suffixes_and_concurrent_calls() {
        assert_eq!(DNSHE_REQUESTS_PER_MINUTE, 30);
        assert_eq!(DNSHE_MIN_REQUEST_INTERVAL, Duration::from_millis(2001));
        assert!(
            DNSHE_MIN_REQUEST_INTERVAL
                .checked_mul(DNSHE_REQUESTS_PER_MINUTE)
                .unwrap()
                > Duration::from_secs(60),
            "31 request starts must span more than a rolling minute"
        );
        let (endpoint, state, handle) = spawn_mock().await;
        let checker = DnsheChecker::for_test(endpoint, DNSHE_MIN_REQUEST_INTERVAL);

        let (first, second, third) = tokio::join!(
            checker.check("taken.l.cd"),
            checker.check("taken.us.ci"),
            checker.check("taken.bot.cd")
        );
        let results = [first, second, third];
        assert_eq!(
            results
                .iter()
                .filter(|result| result.error.is_none())
                .count(),
            1
        );
        assert_eq!(results.iter().filter(|result| result.deferred).count(), 2);
        assert_eq!(state.hits.load(Ordering::SeqCst), 1);
        handle.abort();
    }

    #[tokio::test]
    async fn persistent_limiter_coordinates_checker_instances_and_survives_recreation() {
        let interval = Duration::from_millis(80);
        let (endpoint, state, handle) = spawn_mock().await;
        let db = persistent_rate_pool().await;
        let first = DnsheChecker::for_test_with_db(endpoint.clone(), interval, db.clone());
        let second = DnsheChecker::for_test_with_db(endpoint.clone(), interval, db.clone());

        let (left, right) = tokio::join!(first.check("taken.l.cd"), second.check("taken.us.ci"));
        assert_eq!(
            [&left, &right]
                .into_iter()
                .filter(|result| result.error.is_none() && !result.deferred)
                .count(),
            1
        );
        assert_eq!(
            [&left, &right]
                .into_iter()
                .filter(|result| result.deferred)
                .count(),
            1
        );
        assert_eq!(state.hits.load(Ordering::SeqCst), 1);

        // A newly built checker has no in-memory history. The persisted row
        // must still block it until the original slot expires.
        let recreated = DnsheChecker::for_test_with_db(endpoint.clone(), interval, db.clone());
        let before_expiry = recreated.check("taken.bot.cd").await;
        assert!(before_expiry.deferred);
        assert_eq!(state.hits.load(Ordering::SeqCst), 1);

        tokio::time::sleep(interval + Duration::from_millis(30)).await;
        let after_expiry = DnsheChecker::for_test_with_db(endpoint, interval, db)
            .check("taken.de5.net")
            .await;
        assert!(after_expiry.error.is_none(), "{after_expiry:?}");
        assert!(!after_expiry.deferred);
        assert_eq!(state.hits.load(Ordering::SeqCst), 2);
        handle.abort();
    }

    #[tokio::test]
    async fn persistent_limiter_fails_closed_when_its_table_is_unavailable() {
        let (endpoint, state, handle) = spawn_mock().await;
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let checker = DnsheChecker::for_test_with_db(endpoint, Duration::ZERO, db);

        let result = checker.check("taken.us.ci").await;

        assert!(result.deferred);
        assert!(result.retryable);
        assert_eq!(state.hits.load(Ordering::SeqCst), 0);
        handle.abort();
    }

    #[tokio::test]
    async fn persistent_claim_timestamps_after_waiting_for_the_sqlite_write_lock() {
        let interval = Duration::from_millis(80);
        let database_path = std::env::temp_dir().join(format!(
            "domain-scanner-dnshe-rate-{}.db",
            uuid::Uuid::new_v4()
        ));
        let options = SqliteConnectOptions::new()
            .filename(&database_path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_secs(2));
        let first_pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options.clone())
            .await
            .unwrap();
        let second_pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .unwrap();
        sqlx::query(DNSHE_RATE_LIMIT_SCHEMA_SQL)
            .execute(&first_pool)
            .await
            .unwrap();

        let (endpoint, state, handle) = spawn_mock().await;
        let write_lock = first_pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
        let waiting_checker =
            DnsheChecker::for_test_with_db(endpoint.clone(), interval, second_pool.clone());
        let waiting_request =
            tokio::spawn(async move { waiting_checker.check("taken.l.cd").await });

        // Hold the lock longer than the configured interval. A timestamp taken
        // before lock acquisition would already be expired when this commits.
        tokio::time::sleep(interval + Duration::from_millis(40)).await;
        write_lock.commit().await.unwrap();
        let first_result = waiting_request.await.unwrap();
        assert!(first_result.error.is_none(), "{first_result:?}");
        assert!(!first_result.deferred);
        assert_eq!(state.hits.load(Ordering::SeqCst), 1);

        let next_checker = DnsheChecker::for_test_with_db(endpoint, interval, first_pool.clone());
        let immediate_next = next_checker.check("taken.us.ci").await;
        assert!(immediate_next.deferred);
        assert_eq!(state.hits.load(Ordering::SeqCst), 1);

        handle.abort();
        first_pool.close().await;
        second_pool.close().await;
        let _ = std::fs::remove_file(&database_path);
        let _ = std::fs::remove_file(database_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(database_path.with_extension("db-shm"));
    }

    #[tokio::test]
    async fn maps_provider_backoff_and_disables_rejected_authentication() {
        let (endpoint, state, handle) = spawn_mock().await;
        let checker = DnsheChecker::for_test(endpoint, Duration::ZERO);

        let limited = checker.check("limited.us.ci").await;
        assert!(limited.rate_limited);
        assert_eq!(limited.retry_after_secs, Some(7));
        let after_limit = checker.check("free.us.ci").await;
        assert!(after_limit.deferred);
        assert_eq!(state.hits.load(Ordering::SeqCst), 1);

        let auth_checker = DnsheChecker::for_test(checker.endpoint.clone(), Duration::ZERO);
        let unauthorized = auth_checker.check("unauthorized.us.ci").await;
        assert!(unauthorized.error.is_some());
        assert!(!unauthorized.retryable);
        let hits_after_rejection = state.hits.load(Ordering::SeqCst);
        let rejected_again = auth_checker.check("taken.us.ci").await;
        assert!(rejected_again.error.is_some());
        assert_eq!(state.hits.load(Ordering::SeqCst), hits_after_rejection);
        handle.abort();
    }

    #[tokio::test]
    async fn transient_server_errors_are_retryable() {
        let (endpoint, _state, handle) = spawn_mock().await;
        let checker = DnsheChecker::for_test(endpoint, Duration::ZERO);
        let result = checker.check("server-error.us.ci").await;
        assert!(result.retryable);
        assert!(!result.registration_record_absent);
        assert_eq!(result.retry_after_secs, Some(30));
        handle.abort();
    }

    #[test]
    fn debug_output_never_contains_credentials() {
        let checker = DnsheChecker::for_test(
            Url::parse("http://127.0.0.1:9/?m=domain_hub").unwrap(),
            Duration::ZERO,
        );
        let debug = format!("{checker:?}");
        assert!(!debug.contains("test-key"));
        assert!(!debug.contains("test-secret"));
        assert!(debug.contains("credentials_configured"));
    }

    #[tokio::test]
    async fn live_dnshe_api_mapping_when_enabled() {
        if env::var("DOMAIN_SCANNER_LIVE_TESTS").as_deref() != Ok("1")
            || env::var_os(DNSHE_API_KEY_ENV).is_none()
            || env::var_os(DNSHE_API_SECRET_ENV).is_none()
        {
            return;
        }
        let db = persistent_rate_pool().await;
        let checker = DnsheChecker::from_env_with_db(db);
        let result = checker.check("www.us.ci").await;
        assert!(result.error.is_none(), "{result:?}");
        assert!(result.has_registration_evidence(), "{result:?}");
        assert_eq!(result.signatures, vec!["DNSHE"]);
    }
}
