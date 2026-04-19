//! Checker Registry
//!
//! Manages a collection of domain checkers and orchestrates domain checking.

use std::collections::HashMap;
use std::sync::Arc;

use super::doh::DohChecker;
use super::local::LocalReservedChecker;
use super::rdap::RdapChecker;
use super::traits::{CheckResult, DomainChecker};
use super::whois::WhoisChecker;
use crate::config::AppConfig;
use tracing::{debug, error, info, warn};

/// Registry that manages multiple domain checkers.
///
/// The registry runs checkers in priority order and combines their results.
#[derive(Debug)]
pub struct CheckerRegistry {
    checkers: Vec<Arc<dyn DomainChecker>>,
}

impl CheckerRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            checkers: Vec::new(),
        }
    }

    /// Create a registry with the default set of checkers.
    ///
    /// Default checkers (in priority order):
    /// 1. `LocalReservedChecker` �?fast local reserved-name check (no network)
    /// 2. `DohChecker`           �?DNS-over-HTTPS
    /// 3. `RdapChecker`          �?RDAP protocol
    /// 4. `WhoisChecker`         �?legacy WHOIS fallback
    ///
    /// `whois_servers` is loaded from the database (merged with config.json overrides)
    /// by the caller before this function is invoked.
    pub async fn with_defaults(config: AppConfig, whois_servers: HashMap<String, String>) -> Self {
        let mut registry = Self::new();

        registry.add_checker(Arc::new(LocalReservedChecker::new()));

        let doh_checker = DohChecker::with_servers(config.doh_servers.clone()).await;
        registry.add_checker(Arc::new(doh_checker));

        registry.add_checker(Arc::new(
            RdapChecker::with_config(
                config.rdap_servers.clone(),
                config.rdap_bootstrap_url.clone(),
            )
            .await,
        ));

        // WHOIS server map comes from DB defaults + config.json overrides (caller merges).
        registry.add_checker(Arc::new(WhoisChecker::with_servers(whois_servers)));

        registry.sort_by_priority();
        info!(
            target: "domain_scanner::checker::registry",
            context = "startup",
            order = %registry.checker_names().join(" -> "),
            "checker registry order ready"
        );
        registry
    }

    pub fn clone_for_runtime(&self) -> Self {
        Self {
            checkers: self.checkers.clone(),
        }
    }

    /// Add a checker to the registry.
    pub fn add_checker(&mut self, checker: Arc<dyn DomainChecker>) {
        self.checkers.push(checker);
    }

    /// Sort checkers by priority (lowest value = checked first).
    pub fn sort_by_priority(&mut self) {
        self.checkers.sort_by_key(|c| c.priority());
    }

    /// Check a domain using all registered checkers.
    ///
    /// Checkers are run in priority order. If a checker returns a definitive
    /// result (managed by `should_stop_pipeline`), subsequent checkers are skipped.
    pub async fn check(&self, domain: &str) -> CheckResult {
        if domain.matches('.').count() < 1 {
            warn!(
                target: "domain_scanner::checker::registry",
                context = "validation",
                domain,
                "rejected invalid domain format"
            );
            return CheckResult::error("Invalid domain format");
        }

        let mut all_signatures = Vec::new();
        let mut available = true;
        let mut last_error: Option<String> = None;
        let mut last_retryable: Option<CheckResult> = None;
        let mut authoritative_result: Option<CheckResult> = None;
        let mut trace_log = Vec::new();

        for checker in &self.checkers {
            if !checker.supports_domain(domain) {
                trace_log.push(format!("{}: skipped unsupported suffix", checker.name()));
                continue;
            }

            let result = checker.check(domain).await;
            trace_log.extend(result.trace.clone());

            if result.rate_limited {
                warn!(
                    target: "domain_scanner::checker::registry",
                    context = "pipeline",
                    checker = checker.name(),
                    domain,
                    reason = result.error.as_deref().unwrap_or("rate limited"),
                    "stopping pipeline on rate limit"
                );
                let mut result = result;
                result.trace = trace_log;
                return result;
            }

            if let Some(err) = &result.error {
                debug!(
                    target: "domain_scanner::checker::registry",
                    context = "pipeline",
                    checker = checker.name(),
                    domain,
                    error = %err,
                    retryable = result.retryable,
                    "checker returned error"
                );
                last_error = Some(err.clone());
                if result.retryable {
                    last_retryable = Some(result.clone());
                }
                continue; // Try next checker on error
            }

            all_signatures.extend(result.signatures.clone());

            if !result.available {
                available = false;
            }

            if checker.should_stop_pipeline(&result) {
                authoritative_result = Some(result);
                break;
            }
        }

        if let Some(final_res) = authoritative_result {
            if final_res.available {
                let mut result = CheckResult::available();
                result.trace = trace_log;
                return result;
            } else {
                let mut res = CheckResult::registered(all_signatures);
                res.error = None;
                res.trace = trace_log;
                return res;
            }
        }

        if !available {
            let mut result = CheckResult::registered(all_signatures);
            result.trace = trace_log;
            result
        } else if let Some(retryable) = last_retryable {
            let mut result = retryable;
            result.trace = trace_log;
            result
        } else if let Some(err) = last_error {
            if all_signatures.is_empty() {
                error!(
                    target: "domain_scanner::checker::registry",
                    context = "pipeline",
                    domain,
                    error = %err,
                    "returning terminal error"
                );
                let mut result = CheckResult::error(err);
                result.trace = trace_log;
                result
            } else {
                let mut result = CheckResult::available();
                result.trace = trace_log;
                result
            }
        } else {
            let mut result = CheckResult::available();
            result.trace = trace_log;
            result
        }
    }

    /// Get the list of registered checker names.
    pub fn checker_names(&self) -> Vec<&'static str> {
        self.checkers.iter().map(|c| c.name()).collect()
    }
}
