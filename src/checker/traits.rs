//! Domain Checker Trait and Common Types
//!
//! This module defines the core trait for domain registration-record checking.
//! All domain checker implementations must implement the `DomainChecker` trait.
//!
//! # How to Add a New Checker
//!
//! 1. Create a new file in `src/checker/` (e.g., `my_checker.rs`)
//! 2. Implement the `DomainChecker` trait for your checker
//! 3. Add `pub mod my_checker;` to `src/checker/mod.rs`
//! 4. Register your checker in `CheckerRegistry` in `src/checker/registry.rs`
//!
//! See `doh.rs` and `whois.rs` for reference implementations.

use async_trait::async_trait;
use std::fmt::Debug;
use std::future::Future;
use std::sync::Arc;
use tokio::sync::{AcquireError, OwnedSemaphorePermit, Semaphore};

tokio::task_local! {
    static NETWORK_PERMITS: Arc<Semaphore>;
}

pub(crate) async fn with_network_permits<T>(
    permits: Arc<Semaphore>,
    future: impl Future<Output = T>,
) -> T {
    NETWORK_PERMITS.scope(permits, future).await
}

/// Acquire a global slot immediately before network I/O. Direct checker tests
/// do not install a task-local semaphore and therefore run without a slot.
pub(crate) async fn acquire_network_permit() -> Result<Option<OwnedSemaphorePermit>, AcquireError> {
    match NETWORK_PERMITS.try_with(Clone::clone) {
        Ok(permits) => permits.acquire_owned().await.map(Some),
        Err(_) => Ok(None),
    }
}

/// Result of a domain check operation
#[derive(Debug, Clone)]
pub struct CheckResult {
    /// Whether an authoritative registration-data source reported no record.
    ///
    /// This does not mean that the domain can actually be purchased. Registries
    /// may still reserve or specially price names that have no RDAP/WHOIS record.
    pub registration_record_absent: bool,
    /// Signatures/indicators found (e.g., "DNS", "RDAP", "WHOIS")
    pub signatures: Vec<String>,
    /// Error message if the check failed
    pub error: Option<String>,
    /// Expiration date if the domain is registered
    pub expiration_date: Option<String>,
    /// Whether the checker hit a rate limit and the scan should be retried later
    pub rate_limited: bool,
    /// Whether this error is transient and the same domain should be retried later
    pub retryable: bool,
    /// Suggested delay before retrying the same domain
    pub retry_after_secs: Option<u64>,
    /// Pipeline trace collected from the contributing checkers
    pub trace: Vec<String>,
}

impl CheckResult {
    /// Create a result indicating that no registration record was found.
    pub fn no_registration_record() -> Self {
        Self {
            registration_record_absent: true,
            signatures: vec![],
            error: None,
            expiration_date: None,
            rate_limited: false,
            retryable: false,
            retry_after_secs: None,
            trace: vec![],
        }
    }

    /// Create a new result indicating the domain is registered/taken
    pub fn registered(signatures: Vec<String>) -> Self {
        Self {
            registration_record_absent: false,
            signatures,
            error: None,
            expiration_date: None,
            rate_limited: false,
            retryable: false,
            retry_after_secs: None,
            trace: vec![],
        }
    }

    /// Create a new result with expiration date
    pub fn registered_with_expiry(signatures: Vec<String>, expiry: Option<String>) -> Self {
        Self {
            registration_record_absent: false,
            signatures,
            error: None,
            expiration_date: expiry,
            rate_limited: false,
            retryable: false,
            retry_after_secs: None,
            trace: vec![],
        }
    }

    /// Create a new result indicating an error occurred
    pub fn error(msg: impl Into<String>) -> Self {
        Self {
            registration_record_absent: false,
            signatures: vec![],
            error: Some(msg.into()),
            expiration_date: None,
            rate_limited: false,
            retryable: false,
            retry_after_secs: None,
            trace: vec![],
        }
    }

    pub fn rate_limited(msg: impl Into<String>) -> Self {
        Self::rate_limited_with_retry(msg, None)
    }

    pub fn rate_limited_with_retry(msg: impl Into<String>, retry_after_secs: Option<u64>) -> Self {
        Self {
            registration_record_absent: false,
            signatures: vec![],
            error: Some(msg.into()),
            expiration_date: None,
            rate_limited: true,
            retryable: true,
            retry_after_secs,
            trace: vec![],
        }
    }

    pub fn retryable_error(msg: impl Into<String>, retry_after_secs: Option<u64>) -> Self {
        Self {
            registration_record_absent: false,
            signatures: vec![],
            error: Some(msg.into()),
            expiration_date: None,
            rate_limited: false,
            retryable: true,
            retry_after_secs,
            trace: vec![],
        }
    }

    /// Create a successful but inconclusive result.
    pub fn unknown() -> Self {
        Self {
            registration_record_absent: false,
            signatures: vec![],
            error: None,
            expiration_date: None,
            rate_limited: false,
            retryable: false,
            retry_after_secs: None,
            trace: vec![],
        }
    }

    pub fn has_registration_evidence(&self) -> bool {
        !self.registration_record_absent && !self.signatures.is_empty() && self.error.is_none()
    }

    pub fn with_trace(mut self, entry: impl Into<String>) -> Self {
        self.trace.push(entry.into());
        self
    }
}

/// Priority level for checkers
/// Lower values = higher priority (checked first)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CheckerPriority {
    /// Fastest checks (e.g., local reserved rules)
    Local = 0,
    /// Fast network checks (e.g., DNS over HTTPS)
    Fast = 10,
    /// Standard network checks (e.g., RDAP)
    Standard = 20,
    /// Slow/fallback checks (e.g., legacy WHOIS)
    Fallback = 30,
}

/// Trait for domain registration-record checkers
///
/// Implement this trait to add a new domain checking method.
///
/// # Example
///
/// ```rust,ignore
/// use async_trait::async_trait;
/// use crate::checker::{DomainChecker, CheckResult, CheckerPriority};
///
/// pub struct MyCustomChecker {
///     // Your checker's configuration
/// }
///
/// #[async_trait]
/// impl DomainChecker for MyCustomChecker {
///     fn name(&self) -> &'static str {
///         "MyCustomChecker"
///     }
///
///     fn priority(&self) -> CheckerPriority {
///         CheckerPriority::Standard
///     }
///
///     async fn check(&self, domain: &str) -> CheckResult {
///         // Your implementation here
///         CheckResult::unknown()
///     }
///
///     fn supports_tld(&self, tld: &str) -> bool {
///         // Return true if this checker supports the given TLD
///         true
///     }
/// }
/// ```
#[async_trait]
pub trait DomainChecker: Send + Sync + Debug {
    /// Returns the name of this checker (for logging and signatures)
    fn name(&self) -> &'static str;

    /// Returns the priority of this checker
    fn priority(&self) -> CheckerPriority;

    /// Check a domain for registration-record evidence
    ///
    /// # Arguments
    /// * `domain` - The full domain name to check (e.g., "example.com")
    ///
    /// # Returns
    /// A `CheckResult` describing registration-record evidence and any errors
    async fn check(&self, domain: &str) -> CheckResult;

    /// Check if this checker supports a given TLD
    ///
    /// # Arguments
    /// * `tld` - The TLD without the leading dot (e.g., "com", "li")
    ///
    /// # Returns
    /// `true` if this checker can handle domains with this TLD
    fn supports_tld(&self, tld: &str) -> bool;

    /// Resolve the longest supported suffix for a domain.
    fn matching_suffix(&self, domain: &str) -> Option<String> {
        domain_suffix_candidates(domain)
            .into_iter()
            .find(|suffix| self.supports_tld(suffix))
    }

    /// Check whether this checker supports the domain's effective suffix.
    fn supports_domain(&self, domain: &str) -> bool {
        self.matching_suffix(domain).is_some()
    }

    /// Determine if the checking pipeline should stop after this result.
    ///
    /// # Arguments
    /// * `result` - The result returned by this checker's `check` method
    ///
    /// # Returns
    /// `true` if this result is definitive and subsequent checkers should be skipped.
    fn should_stop_pipeline(&self, result: &CheckResult) -> bool {
        self.is_authoritative() && result.has_registration_evidence()
    }

    /// Whether this checker can definitively determine registration status
    /// (Deprecated: use `should_stop_pipeline` for more control)
    fn is_authoritative(&self) -> bool {
        false
    }
}

pub fn domain_suffix_candidates(domain: &str) -> Vec<String> {
    let labels: Vec<&str> = domain
        .split('.')
        .map(str::trim)
        .filter(|label| !label.is_empty())
        .collect();

    if labels.len() < 2 {
        return Vec::new();
    }

    let mut suffixes = Vec::with_capacity(labels.len() - 1);
    for idx in 1..labels.len() {
        suffixes.push(labels[idx..].join(".").to_ascii_lowercase());
    }
    suffixes
}
