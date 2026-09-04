//! Local Reserved Domain Checker
//!
//! This checker uses local rules to identify reserved domains
//! without making any network requests. It's the fastest checker.

use async_trait::async_trait;
use std::collections::HashSet;
use std::sync::LazyLock;

use super::traits::{CheckResult, CheckerPriority, DomainChecker};

// Conservative list of strictly reserved words (RFC 2606, etc.)
// These are names that are technically reserved or invalid for registration
// across standardized TLDs.
static RESERVED_WORDS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    let mut s = HashSet::new();
    let words = vec![
        // RFC 2606 Reserved Names
        "example",
        "invalid",
        "localhost",
        "test",
        // Special use
        "local",
        "onion",
        // Standard Restrictions (often blocked at registry level)
        "www",
        "nic",
        "whois",
        "arpa",
    ];
    for w in words {
        s.insert(w);
    }
    s
});

fn is_reserved_domain(domain: &str) -> bool {
    let domain_lower = domain.to_lowercase();
    let parts: Vec<&str> = domain_lower.split('.').collect();

    if parts.is_empty() {
        return false;
    }

    // Check strict lists based on the SLD (Second Level Domain) or the first part
    // For "example.com", we check "example"
    let sld = parts[0];

    if RESERVED_WORDS.contains(sld) {
        return true;
    }

    false
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

        // 1. Test reserved word (RFC 2606)
        let result = checker.check("example.com").await;
        assert!(
            !result.registration_record_absent,
            "example.com should be reserved locally"
        );
        assert!(result.signatures.contains(&"RESERVED".to_string()));

        // 2. Test strictly reserved technical term
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
    }
}
