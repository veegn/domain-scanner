//! Local Reserved Domain Checker
//!
//! This checker uses local rules to identify reserved domains
//! without making any network requests. It's the fastest checker.

use async_trait::async_trait;

use super::traits::{CheckResult, CheckerPriority, DomainChecker};
use crate::reserved;

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
        if reserved::is_reserved_domain(domain) {
            CheckResult::registered(vec!["RESERVED".to_string()])
        } else {
            CheckResult::available()
        }
    }

    fn supports_tld(&self, _tld: &str) -> bool {
        // Local checker works for all TLDs
        true
    }

    fn is_authoritative(&self) -> bool {
        // If we say it's reserved, it's definitely not available
        // But if we say it's available, we need confirmation from network checkers
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_local_reserved() {
        let checker = LocalReservedChecker::new();

        // 1. Test reserved word
        let result = checker.check("google.com").await;
        assert!(!result.available, "google.com should be reserved locally");
        assert!(result.signatures.contains(&"RESERVED".to_string()));

        // 2. Test reserved pattern (single letter)
        let result = checker.check("a.com").await;
        assert!(!result.available, "a.com should be reserved locally");

        // 3. Test non-reserved domain
        let result = checker.check("myveryuniqdomain123456.com").await;
        assert!(
            result.available,
            "random long domain should not be reserved locally"
        );
    }
}
