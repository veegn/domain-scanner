//! Checker Registry
//!
//! Manages a collection of domain checkers and orchestrates domain checking.

use std::sync::Arc;

use super::doh::DohChecker;
use super::local::LocalReservedChecker;
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
    pub async fn with_defaults(config: AppConfig) -> Self {
        let mut registry = Self::new();

        // Add local reserved checker (highest priority)
        registry.add_checker(Arc::new(LocalReservedChecker::new()));

        // Add DoH checker
        // Use doh_servers from config
        let servers = config.doh_servers.clone();

        let doh_checker = DohChecker::with_servers(servers).await;
        registry.add_checker(Arc::new(doh_checker));

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
    /// result (managed by `should_stop_pipeline`), subsequent checkers are skipped.
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
        let mut authoritative_result: Option<CheckResult> = None;

        for checker in &self.checkers {
            // Skip checkers that don't support this TLD
            if !checker.supports_tld(tld) {
                continue;
            }

            let result = checker.check(domain).await;

            // Collect error (don't stop pipeline just for error usually, unless we want strict fail)
            if let Some(err) = &result.error {
                last_error = Some(err.clone());
                // If it's an error, we usually try the next checker (fallback)
                // UNLESS the checker says we should stop even on error?
                // For now, continue to next checker on error
                continue;
            }

            // If we have a valid result (no error)
            all_signatures.extend(result.signatures.clone());

            if !result.available {
                available = false; // Mark as found/registered

            // If this is authoritative for "Registered", we can stop.
            } else {
                // It says available.
            }

            // Check if we should stop the pipeline based on this result
            if checker.should_stop_pipeline(&result) {
                authoritative_result = Some(result);
                break;
            }
        }

        if let Some(final_res) = authoritative_result {
            // If we broke early because of an authoritative result
            if final_res.available {
                return CheckResult::available();
            } else {
                // return accumulated signatures or just this one?
                // Usually accumulated signatures are better if we had multiple checks (e.g. Local + DoH)
                // But if we stopped at Local, we only have Local.
                // If we stopped at DoH, we have Local + DoH.
                // We should merge signatures.
                let mut res = CheckResult::registered(all_signatures);
                res.error = last_error;
                return res;
            }
        }

        // If we went through all checkers (or only non-authoritative ones)
        if !available {
            CheckResult::registered(all_signatures)
        } else if let Some(err) = last_error {
            // All checkers failed with errors
            if all_signatures.is_empty() {
                CheckResult::error(err)
            } else {
                // Some succeeded, some failed - return what we have (likely available if we got here)
                // But wait, if available remained true, and we had signatures?
                // If signatures exist, available should be false.
                CheckResult::available()
            }
        } else {
            // No errors, available remained true
            CheckResult::available()
        }
    }

    /// Get the list of registered checker names
    pub fn checker_names(&self) -> Vec<&'static str> {
        self.checkers.iter().map(|c| c.name()).collect()
    }
}
