//! Checker Registry
//!
//! Manages a collection of domain checkers and orchestrates domain checking.

use std::sync::Arc;

use super::doh::DohChecker;
use super::local::LocalReservedChecker;
use super::rdap::RdapChecker;
use super::traits::{CheckResult, DomainChecker};
use super::whois::WhoisChecker;
use crate::config::AppConfig;

/// Registry that manages multiple domain checkers
///
/// The registry runs checkers in priority order and combines their results.
#[derive(Debug)]
pub struct CheckerRegistry {
    checkers: Vec<Arc<dyn DomainChecker>>,
}

impl CheckerRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            checkers: Vec::new(),
        }
    }

    /// Create a registry with the default set of checkers
    ///
    /// Default checkers (in priority order):
    /// 1. LocalReservedChecker - checks local reserved rules
    /// 2. DohChecker - DNS over HTTPS check
    /// 3. RdapChecker - RDAP registry check
    pub fn with_defaults(config: AppConfig) -> Self {
        let mut registry = Self::new();

        // Add local reserved checker (highest priority)
        registry.add_checker(Arc::new(LocalReservedChecker::new()));

        // Add DoH checker
        let doh_checker = match config.doh_url {
            Some(url) => DohChecker::with_url(url),
            None => DohChecker::new(),
        };
        registry.add_checker(Arc::new(doh_checker));

        // Add RDAP checker with custom endpoints
        let mut rdap = RdapChecker::new();
        rdap.custom_endpoints = config.rdap_endpoints;
        registry.add_checker(Arc::new(rdap));

        // Add Whois checker (fallback)
        registry.add_checker(Arc::new(WhoisChecker::new()));

        // Sort by priority
        registry.sort_by_priority();

        registry
    }

    /// Add a checker to the registry
    pub fn add_checker(&mut self, checker: Arc<dyn DomainChecker>) {
        self.checkers.push(checker);
    }

    /// Sort checkers by priority (lowest priority value = checked first)
    pub fn sort_by_priority(&mut self) {
        self.checkers.sort_by_key(|c| c.priority());
    }

    /// Check a domain using all registered checkers
    ///
    /// Checkers are run in priority order. If a checker returns a definitive
    /// result (registered with authoritative checker), subsequent checkers
    /// may be skipped.
    ///
    /// # Arguments
    /// * `domain` - The domain to check
    ///
    /// # Returns
    /// Combined result from all checkers
    pub async fn check(&self, domain: &str) -> CheckResult {
        let parts: Vec<&str> = domain.split('.').collect();
        let tld = if parts.len() > 1 {
            *parts.last().unwrap()
        } else {
            return CheckResult::error("Invalid domain format");
        };

        let mut all_signatures = Vec::new();
        let mut available = true;
        let mut last_error: Option<String> = None;

        for checker in &self.checkers {
            // Skip checkers that don't support this TLD
            if !checker.supports_tld(tld) {
                continue;
            }

            let result = checker.check(domain).await;

            // Collect error but continue
            if let Some(err) = result.error {
                last_error = Some(err);
                continue; // Try next checker
            }

            // Collect signatures
            all_signatures.extend(result.signatures);

            // If any checker says it's not available, mark as unavailable
            if !result.available {
                available = false;

                // If this checker is authoritative, we can stop here
                if checker.is_authoritative() {
                    break;
                }
            }
        }

        if !available {
            CheckResult::registered(all_signatures)
        } else if let Some(err) = last_error {
            // All checkers failed with errors
            if all_signatures.is_empty() {
                CheckResult::error(err)
            } else {
                // Some succeeded, some failed - return what we have
                CheckResult::available()
            }
        } else {
            CheckResult::available()
        }
    }

    /// Get the list of registered checker names
    pub fn checker_names(&self) -> Vec<&'static str> {
        self.checkers.iter().map(|c| c.name()).collect()
    }
}

impl Default for CheckerRegistry {
    fn default() -> Self {
        Self::with_defaults(AppConfig::default())
    }
}
