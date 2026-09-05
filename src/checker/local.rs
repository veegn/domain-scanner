//! Local Reserved Domain Checker
//!
//! This checker uses local rules to identify reserved domains
//! without making any network requests. It's the fastest checker.

use async_trait::async_trait;
use std::collections::HashSet;
use std::sync::LazyLock;

use super::traits::{CheckResult, CheckerPriority, DomainChecker};

// IANA special-use names apply to the listed domain and its descendants. They
// are suffix rules; a label such as `test` is not reserved under every TLD.
static SPECIAL_USE_SUFFIXES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        "alt",
        "arpa",
        "example",
        "example.com",
        "example.net",
        "example.org",
        "invalid",
        "local",
        "localhost",
        "onion",
        "test",
    ])
});

fn is_reserved_domain(domain: &str) -> bool {
    let domain_lower = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    SPECIAL_USE_SUFFIXES
        .iter()
        .any(|suffix| domain_lower == *suffix || domain_lower.ends_with(&format!(".{suffix}")))
}

/// Local reserved domain checker
///
/// Checks domains against local rules for reserved patterns, TLD-specific
/// reserved names, and other policy-based restrictions.
#[derive(Debug, Clone, Default)]
pub struct LocalReservedChecker;

impl LocalReservedChecker {
    /// Create a new local reserved checker
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl DomainChecker for LocalReservedChecker {
    fn name(&self) -> &'static str {
        "LocalReserved"
    }

    fn priority(&self) -> CheckerPriority {
        CheckerPriority::Local
    }

    async fn check(&self, domain: &str) -> CheckResult {
        if is_reserved_domain(domain) {
            CheckResult::registered(vec!["RESERVED".to_string()])
                .with_trace("LocalReserved: reserved keyword matched")
        } else {
            CheckResult::unknown().with_trace("LocalReserved: no local reservation matched")
        }
    }

    fn supports_tld(&self, _tld: &str) -> bool {
        // Local checker works for all TLDs
        true
    }

    fn is_authoritative(&self) -> bool {
        // A reservation match is definitive; a non-match says nothing about registration.
        false
    }

    fn should_stop_pipeline(&self, result: &CheckResult) -> bool {
        // Stop only when a local reservation matched.
        result.has_registration_evidence()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_local_reserved() {
        let checker = LocalReservedChecker::new();

        // RFC 2606 reserves this exact domain and its descendants.
        let result = checker.check("example.com").await;
        assert!(
            !result.registration_record_absent,
            "example.com should be reserved locally"
        );
        assert!(result.signatures.contains(&"RESERVED".to_string()));

        // Special-use single-label names are recognized by this local checker.
        let result = checker.check("localhost").await;
        assert!(
            !result.registration_record_absent,
            "localhost should be reserved locally"
        );

        // 3. Passing the local policy check must remain inconclusive.
        // 'google.com' is registered, but NOT technically reserved by RFC standards, so local checker should pass it.
        let result = checker.check("google.com").await;
        assert!(
            !result.registration_record_absent && result.signatures.is_empty(),
            "google.com should pass locally without implying purchase availability"
        );

        // 4. Test another random domain
        let result = checker.check("myveryuniqdomain123456.com").await;
        assert!(
            !result.registration_record_absent && result.signatures.is_empty(),
            "random long domain should pass locally without implying purchase availability"
        );

        let result = checker.check("test.org").await;
        assert!(
            result.signatures.is_empty(),
            "a first label is not a suffix rule"
        );

        let result = checker.check("anything.test").await;
        assert!(result.signatures.contains(&"RESERVED".to_string()));
    }
}
