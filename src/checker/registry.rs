//! Checker Registry
//!
//! Manages a collection of domain checkers and orchestrates domain checking.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use sqlx::SqlitePool;

use super::dnshe::DnsheChecker;
use super::doh::DohChecker;
use super::local::LocalReservedChecker;
use super::rdap::RdapChecker;
use super::traits::{CheckResult, DomainChecker, with_network_permits};
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

impl Default for CheckerRegistry {
    fn default() -> Self {
        Self::new()
    }
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
    /// 1. `LocalReservedChecker` — fast local reserved-name check (no network)
    /// 2. `DnsheChecker`         — authoritative DNSHE child-domain API
    /// 3. `DohChecker`           — DNS-over-HTTPS
    /// 4. `RdapChecker`          — RDAP protocol
    /// 5. `WhoisChecker`         — legacy WHOIS fallback
    ///
    /// `whois_servers` is loaded from the database (merged with config.json overrides)
    /// by the caller before this function is invoked.
    /// The SQLite gate coordinates the fixed DNSHE request interval across
    /// restarts and across application processes that use the same database.
    pub async fn with_defaults(
        config: AppConfig,
        whois_servers: HashMap<String, String>,
        db: SqlitePool,
    ) -> Self {
        Self::with_dnshe_checker(config, whois_servers, DnsheChecker::from_env_with_db(db)).await
    }

    async fn with_dnshe_checker(
        config: AppConfig,
        whois_servers: HashMap<String, String>,
        dnshe_checker: DnsheChecker,
    ) -> Self {
        let mut registry = Self::new();

        registry.add_checker(Arc::new(LocalReservedChecker::new()));
        registry.add_checker(Arc::new(dnshe_checker));
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
        self.check_from(domain, None).await
    }

    pub async fn check_from(&self, domain: &str, resume_checker: Option<&str>) -> CheckResult {
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
        let mut authoritative_no_record = false;
        let mut last_error: Option<String> = None;
        let mut last_retryable: Option<CheckResult> = None;
        let mut first_unresolved = None;
        let mut request_failed = false;
        let mut trace_log = Vec::new();

        let has_exclusive_route = self
            .checkers
            .iter()
            .any(|checker| checker.exclusive_for_domain(domain));
        let is_eligible = |checker: &Arc<dyn DomainChecker>| {
            !has_exclusive_route
                || checker.priority() == super::traits::CheckerPriority::Local
                || checker.exclusive_for_domain(domain)
        };

        let start = resume_checker
            .and_then(|name| {
                self.checkers
                    .iter()
                    .position(|checker| checker.name() == name)
            })
            .filter(|index| is_eligible(&self.checkers[*index]))
            .unwrap_or(0);

        for checker in &self.checkers[start..] {
            if !is_eligible(checker) {
                trace_log.push(format!(
                    "{}: skipped because another checker owns this domain route",
                    checker.name()
                ));
                continue;
            }
            if !checker.supports_domain(domain) {
                trace_log.push(format!("{}: skipped unsupported suffix", checker.name()));
                continue;
            }

            let started = Instant::now();
            let result = checker.check(domain).await;
            debug!(
                target: "domain_scanner::checker::registry",
                context = "stage_metrics",
                checker = checker.name(),
                domain,
                elapsed_ms = started.elapsed().as_millis() as u64,
                deferred = result.deferred,
                retryable = result.retryable,
                rate_limited = result.rate_limited,
                has_error = result.error.is_some(),
                "checker stage completed"
            );
            trace_log.extend(result.trace.clone());

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
                request_failed |= !result.deferred;
                if result.retryable {
                    first_unresolved.get_or_insert_with(|| checker.name().to_string());
                    if last_retryable.as_ref().is_none_or(|previous| {
                        result.retry_after_secs.unwrap_or(30)
                            < previous.retry_after_secs.unwrap_or(30)
                    }) {
                        last_retryable = Some(result.clone());
                    }
                }

                if checker.is_authoritative() && !result.deferred {
                    warn!(
                        target: "domain_scanner::checker::registry",
                        context = "pipeline",
                        checker = checker.name(),
                        domain,
                        error = %err,
                        retryable = result.retryable,
                        "authoritative checker failed; trying the next supported checker"
                    );
                }
                continue; // Try next checker on error
            }

            all_signatures.extend(result.signatures.clone());

            if result.registration_record_absent && checker.is_authoritative() {
                authoritative_no_record = true;
            }

            if checker.should_stop_pipeline(&result) {
                let mut final_result = result;
                if final_result.has_registration_evidence() {
                    final_result.signatures = all_signatures;
                }
                final_result.trace = trace_log;
                return final_result;
            }
        }

        if !all_signatures.is_empty() {
            let mut result = CheckResult::registered(all_signatures);
            result.trace = trace_log;
            result
        } else if authoritative_no_record {
            let mut result = CheckResult::no_registration_record();
            result.trace = trace_log;
            result
        } else if let Some(retryable) = last_retryable {
            let mut result = retryable;
            result.deferred = !request_failed;
            result.resume_checker = first_unresolved;
            result.trace = trace_log;
            result
        } else if let Some(err) = last_error {
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
            let mut result = CheckResult::unknown();
            result.trace = trace_log;
            result
        }
    }

    /// Run the pipeline with a global limit that applies only while a checker
    /// performs network I/O. Admission failures return immediately for the
    /// scheduler to retry, so a cooling provider never occupies global capacity.
    pub async fn check_with_permits(
        &self,
        domain: &str,
        permits: Arc<tokio::sync::Semaphore>,
    ) -> CheckResult {
        with_network_permits(permits, self.check(domain)).await
    }

    pub async fn check_with_permits_from(
        &self,
        domain: &str,
        permits: Arc<tokio::sync::Semaphore>,
        resume_checker: Option<&str>,
    ) -> CheckResult {
        with_network_permits(permits, self.check_from(domain, resume_checker)).await
    }

    /// Get the list of registered checker names.
    pub fn checker_names(&self) -> Vec<&'static str> {
        self.checkers.iter().map(|c| c.name()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct StubChecker {
        name: &'static str,
        priority: super::super::traits::CheckerPriority,
        exclusive: bool,
        result: CheckResult,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl DomainChecker for StubChecker {
        fn name(&self) -> &'static str {
            self.name
        }

        fn priority(&self) -> super::super::traits::CheckerPriority {
            self.priority
        }

        async fn check(&self, _domain: &str) -> CheckResult {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.result.clone()
        }

        fn supports_tld(&self, _tld: &str) -> bool {
            true
        }

        fn exclusive_for_domain(&self, domain: &str) -> bool {
            self.exclusive && domain.ends_with(".us.ci")
        }
    }

    #[tokio::test]
    async fn exclusive_checker_error_never_falls_through_to_generic_sources() {
        let exclusive_calls = Arc::new(AtomicUsize::new(0));
        let fallback_calls = Arc::new(AtomicUsize::new(0));
        let mut registry = CheckerRegistry::new();
        registry.add_checker(Arc::new(StubChecker {
            name: "DNSHE",
            priority: super::super::traits::CheckerPriority::Provider,
            exclusive: true,
            result: CheckResult::retryable_error("DNSHE timeout", Some(30))
                .with_trace("DNSHE: timeout"),
            calls: Arc::clone(&exclusive_calls),
        }));
        registry.add_checker(Arc::new(StubChecker {
            name: "Fallback",
            priority: super::super::traits::CheckerPriority::Fallback,
            exclusive: false,
            result: CheckResult::no_registration_record(),
            calls: Arc::clone(&fallback_calls),
        }));
        registry.sort_by_priority();

        let result = registry.check("name.us.ci").await;

        assert!(result.retryable);
        assert_eq!(result.resume_checker.as_deref(), Some("DNSHE"));
        assert_eq!(exclusive_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fallback_calls.load(Ordering::SeqCst), 0);
        assert!(!result.registration_record_absent);
    }

    #[tokio::test]
    async fn stale_generic_resume_checkpoint_restarts_an_exclusive_route() {
        let exclusive_calls = Arc::new(AtomicUsize::new(0));
        let fallback_calls = Arc::new(AtomicUsize::new(0));
        let mut registry = CheckerRegistry::new();
        registry.add_checker(Arc::new(StubChecker {
            name: "DNSHE",
            priority: super::super::traits::CheckerPriority::Provider,
            exclusive: true,
            result: CheckResult::registered(vec!["DNSHE".to_string()]),
            calls: Arc::clone(&exclusive_calls),
        }));
        registry.add_checker(Arc::new(StubChecker {
            name: "Fallback",
            priority: super::super::traits::CheckerPriority::Fallback,
            exclusive: false,
            result: CheckResult::no_registration_record(),
            calls: Arc::clone(&fallback_calls),
        }));
        registry.sort_by_priority();

        let result = registry.check_from("name.us.ci", Some("Fallback")).await;

        assert!(result.has_registration_evidence());
        assert_eq!(exclusive_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fallback_calls.load(Ordering::SeqCst), 0);
    }
}
