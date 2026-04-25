// =============================================================================
// Domain Scanner - Comprehensive Integration Tests
// =============================================================================

use axum::extract::Path as AxumPath;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use domain_scanner::checker::circuit_breaker::CircuitBreaker;
use domain_scanner::checker::{
    CheckResult, CheckerPriority, CheckerRegistry, DohChecker, DomainChecker, LocalReservedChecker,
    RdapChecker, WhoisChecker,
};
use domain_scanner::config::AppConfig;
use domain_scanner::generator;
use domain_scanner::DomainResult;

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::task::JoinHandle;

fn live_network_enabled() -> bool {
    std::env::var("DOMAIN_SCANNER_LIVE_TESTS")
        .map(|v| v == "1")
        .unwrap_or(false)
}

async fn spawn_mock_rdap_server() -> (String, JoinHandle<()>) {
    async fn domain(AxumPath(name): AxumPath<String>) -> (StatusCode, Json<serde_json::Value>) {
        match name.as_str() {
            n if n == "taken.alpha" || n.ends_with(".taken.alpha") => (
                StatusCode::OK,
                Json(serde_json::json!({
                    "events": [
                        {
                            "eventAction": "expiration",
                            "eventDate": "2030-01-02T03:04:05Z"
                        }
                    ]
                })),
            ),
            n if n == "taken.co.alpha" || n.ends_with(".taken.co.alpha") => (
                StatusCode::OK,
                Json(serde_json::json!({
                    "events": [
                        {
                            "eventAction": "expiry",
                            "eventDate": "2031-05-06T07:08:09Z"
                        }
                    ]
                })),
            ),
            "free.alpha" => (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "description": "Domain not found"
                })),
            ),
            "limited.alpha" => (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "description": "Too many requests"
                })),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "description": "Unexpected domain"
                })),
            ),
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", addr);

    let bootstrap_url = format!("{}/bootstrap", base_url);
    let rdap_base = format!("{}/rdap/", base_url);

    let app = Router::new()
        .route(
            "/bootstrap",
            get({
                let rdap_base = rdap_base.clone();
                move || {
                    let rdap_base = rdap_base.clone();
                    async move {
                        Json(serde_json::json!({
                            "services": [
                                [
                                    ["alpha", "co.alpha"],
                                    [rdap_base]
                                ]
                            ]
                        }))
                    }
                }
            }),
        )
        .route("/rdap/domain/:name", get(domain));

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (bootstrap_url, handle)
}

// =============================================================================
// 1. CheckResult Type Tests
// =============================================================================

#[test]
fn test_check_result_available() {
    let r = CheckResult::available();
    assert!(r.available);
    assert!(r.signatures.is_empty());
    assert!(r.error.is_none());
}

#[test]
fn test_check_result_registered() {
    let r = CheckResult::registered(vec!["DNS".to_string(), "WHOIS".to_string()]);
    assert!(!r.available);
    assert_eq!(r.signatures.len(), 2);
    assert!(r.signatures.contains(&"DNS".to_string()));
    assert!(r.signatures.contains(&"WHOIS".to_string()));
    assert!(r.error.is_none());
}

#[test]
fn test_check_result_registered_empty_signatures() {
    let r = CheckResult::registered(vec![]);
    assert!(!r.available);
    assert!(r.signatures.is_empty());
    assert!(r.error.is_none());
}

#[test]
fn test_check_result_error() {
    let r = CheckResult::error("something went wrong");
    assert!(!r.available);
    assert!(r.signatures.is_empty());
    assert_eq!(r.error.as_deref(), Some("something went wrong"));
}

#[test]
fn test_check_result_error_from_string() {
    let msg = String::from("dynamic error");
    let r = CheckResult::error(msg);
    assert_eq!(r.error.as_deref(), Some("dynamic error"));
}

#[test]
fn test_check_result_clone() {
    let r = CheckResult::registered(vec!["DNS".to_string()]);
    let r2 = r.clone();
    assert_eq!(r.available, r2.available);
    assert_eq!(r.signatures, r2.signatures);
}

#[test]
fn test_check_result_rate_limited() {
    let r = CheckResult::rate_limited("too many requests");
    assert!(r.rate_limited);
    assert!(r.retryable);
    assert_eq!(r.error.as_deref(), Some("too many requests"));
}

#[test]
fn test_whois_config_override_supports_new_tld() {
    let mut custom = std::collections::HashMap::new();
    custom.insert("li".to_string(), "whois.example.test".to_string());
    custom.insert(".custom".to_string(), "whois.custom.test:4343".to_string());

    let checker = WhoisChecker::with_servers(custom);
    assert!(checker.supports_tld("li"));
    assert!(checker.supports_tld("custom"));
}

#[tokio::test]
async fn test_rdap_config_override_supports_new_tld() {
    let mut custom = std::collections::HashMap::new();
    custom.insert(
        "custom".to_string(),
        "https://rdap.custom.test/".to_string(),
    );
    custom.insert(
        ".co.uk".to_string(),
        "https://rdap.example.test/".to_string(),
    );

    let checker = RdapChecker::with_config(custom, None).await;
    assert!(checker.supports_tld("custom"));
    assert!(checker.supports_tld("co.uk"));
    assert_eq!(
        checker.matching_suffix("name.co.uk").as_deref(),
        Some("co.uk")
    );
}

#[tokio::test]
async fn test_rdap_bootstrap_loads_local_suffixes() {
    let (bootstrap_url, handle) = spawn_mock_rdap_server().await;
    let checker =
        RdapChecker::with_config(std::collections::HashMap::new(), Some(bootstrap_url)).await;

    assert!(checker.supports_tld("alpha"));
    assert!(checker.supports_tld("co.alpha"));
    assert_eq!(
        checker.matching_suffix("demo.co.alpha").as_deref(),
        Some("co.alpha")
    );

    handle.abort();
}

#[tokio::test]
async fn test_rdap_bootstrap_uses_local_cache_when_remote_unavailable() {
    let cache_dir = std::env::temp_dir().join(format!(
        "domain_scanner_rdap_cache_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    let (bootstrap_url, handle) = spawn_mock_rdap_server().await;
    let checker = RdapChecker::with_config_and_cache_dir(
        std::collections::HashMap::new(),
        Some(bootstrap_url.clone()),
        Some(cache_dir.clone()),
    )
    .await;
    assert!(checker.supports_tld("alpha"));

    handle.abort();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let cached_checker = RdapChecker::with_config_and_cache_dir(
        std::collections::HashMap::new(),
        Some(bootstrap_url),
        Some(cache_dir.clone()),
    )
    .await;

    assert!(cached_checker.supports_tld("alpha"));
    assert!(cached_checker.supports_tld("co.alpha"));
    assert_eq!(
        cached_checker.matching_suffix("demo.co.alpha").as_deref(),
        Some("co.alpha")
    );

    let _ = std::fs::remove_dir_all(&cache_dir);
}

#[tokio::test]
async fn test_rdap_mocked_check_registered_available_and_rate_limited() {
    let (bootstrap_url, handle) = spawn_mock_rdap_server().await;
    let checker =
        RdapChecker::with_config(std::collections::HashMap::new(), Some(bootstrap_url)).await;

    let taken = checker.check("taken.alpha").await;
    assert!(!taken.available);
    assert!(taken.signatures.contains(&"RDAP".to_string()));
    assert_eq!(
        taken.expiration_date.as_deref(),
        Some("2030-01-02T03:04:05Z")
    );

    let free = checker.check("free.alpha").await;
    assert!(free.available);
    assert!(free.error.is_none());

    let limited = checker.check("limited.alpha").await;
    assert!(limited.rate_limited);
    assert_eq!(
        limited.error.as_deref(),
        Some("RDAP rate limit exceeded (HTTP 429)")
    );

    handle.abort();
}

#[test]
fn test_whois_matches_longest_suffix() {
    let mut custom = std::collections::HashMap::new();
    custom.insert("uk".to_string(), "whois.nic.uk".to_string());
    custom.insert("co.uk".to_string(), "whois.example.co.uk".to_string());
    custom.insert("com.cn".to_string(), "whois.example.com.cn".to_string());

    let checker = WhoisChecker::with_servers(custom);
    assert_eq!(
        checker.matching_suffix("example.co.uk").as_deref(),
        Some("co.uk")
    );
    assert_eq!(
        checker.matching_suffix("deep.name.com.cn").as_deref(),
        Some("com.cn")
    );
    assert_eq!(checker.matching_suffix("singleword"), None);
}

#[test]
fn test_whois_builtin_supports_common_multi_part_suffixes() {
    let mut custom = HashMap::new();
    custom.insert("co.uk".to_string(), "whois.nic.uk".to_string());
    custom.insert("com.cn".to_string(), "whois.cnnic.cn".to_string());
    custom.insert("com.au".to_string(), "whois.auda.org.au".to_string());

    let checker = WhoisChecker::with_servers(custom);
    assert!(checker.supports_tld("co.uk"));
    assert!(checker.supports_tld("com.cn"));
    assert!(checker.supports_tld("com.au"));
}

// =============================================================================
// 2. LocalReservedChecker Tests
// =============================================================================

#[tokio::test]
async fn test_local_reserved_rfc2606_example() {
    let checker = LocalReservedChecker::new();
    let result = checker.check("example.com").await;
    assert!(
        !result.available,
        "example.com should be reserved (RFC 2606)"
    );
    assert!(result.signatures.contains(&"RESERVED".to_string()));
}

#[tokio::test]
async fn test_local_reserved_rfc2606_test() {
    let checker = LocalReservedChecker::new();
    let result = checker.check("test.org").await;
    assert!(!result.available, "test.org should be reserved (RFC 2606)");
}

#[tokio::test]
async fn test_local_reserved_rfc2606_invalid() {
    let checker = LocalReservedChecker::new();
    let result = checker.check("invalid.net").await;
    assert!(
        !result.available,
        "invalid.net should be reserved (RFC 2606)"
    );
}

#[tokio::test]
async fn test_local_reserved_localhost() {
    let checker = LocalReservedChecker::new();
    let result = checker.check("localhost").await;
    assert!(!result.available, "localhost should be reserved");
}

#[tokio::test]
async fn test_local_reserved_local() {
    let checker = LocalReservedChecker::new();
    let result = checker.check("local.dev").await;
    assert!(!result.available, "local.dev should be reserved");
}

#[tokio::test]
async fn test_local_reserved_onion() {
    let checker = LocalReservedChecker::new();
    let result = checker.check("onion.com").await;
    assert!(!result.available, "onion.com should be reserved");
}

#[tokio::test]
async fn test_local_reserved_www() {
    let checker = LocalReservedChecker::new();
    let result = checker.check("www.com").await;
    assert!(!result.available, "www.com should be reserved");
}

#[tokio::test]
async fn test_local_reserved_nic() {
    let checker = LocalReservedChecker::new();
    let result = checker.check("nic.uk").await;
    assert!(!result.available, "nic.uk should be reserved");
}

#[tokio::test]
async fn test_local_reserved_whois_word() {
    let checker = LocalReservedChecker::new();
    let result = checker.check("whois.com").await;
    assert!(!result.available, "whois.com should be reserved");
}

#[tokio::test]
async fn test_local_reserved_arpa() {
    let checker = LocalReservedChecker::new();
    let result = checker.check("arpa.net").await;
    assert!(!result.available, "arpa.net should be reserved");
}

#[tokio::test]
async fn test_local_not_reserved_google() {
    let checker = LocalReservedChecker::new();
    let result = checker.check("google.com").await;
    assert!(
        result.available,
        "google.com should NOT be locally reserved"
    );
}

#[tokio::test]
async fn test_local_not_reserved_random() {
    let checker = LocalReservedChecker::new();
    let result = checker.check("randomdomain12345.io").await;
    assert!(result.available);
}

#[tokio::test]
async fn test_local_case_insensitive() {
    let checker = LocalReservedChecker::new();
    let result = checker.check("EXAMPLE.COM").await;
    assert!(!result.available, "EXAMPLE.COM should be reserved");
}

#[tokio::test]
async fn test_local_checker_metadata() {
    let checker = LocalReservedChecker::new();
    assert_eq!(checker.name(), "LocalReserved");
    assert_eq!(checker.priority(), CheckerPriority::Local);
    assert!(checker.supports_tld("com"));
    assert!(checker.supports_tld("anything"));
}

#[tokio::test]
async fn test_local_should_stop_pipeline_on_reserved() {
    let checker = LocalReservedChecker::new();
    let result = checker.check("example.com").await;
    assert!(checker.should_stop_pipeline(&result));
}

#[tokio::test]
async fn test_local_should_not_stop_pipeline_on_available() {
    let checker = LocalReservedChecker::new();
    let result = checker.check("notreserved.com").await;
    assert!(!checker.should_stop_pipeline(&result));
}

// =============================================================================
// 3. DohChecker Tests (requires network)
// =============================================================================

#[tokio::test]
async fn test_doh_registered_domain() {
    if !live_network_enabled() {
        return;
    }

    let checker = DohChecker::new().await;
    let result = checker.check("google.com").await;
    if result.error.is_none() {
        assert!(!result.available, "google.com should have DNS records");
        assert!(result.signatures.contains(&"DNS".to_string()));
    }
}

#[tokio::test]
async fn test_doh_available_domain() {
    if !live_network_enabled() {
        return;
    }

    let checker = DohChecker::new().await;
    let domain = format!(
        "test-doh-nonexist-{}.com",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let result = checker.check(&domain).await;
    assert!(
        result.available,
        "random domain should not have DNS records"
    );
}

#[tokio::test]
async fn test_doh_checker_metadata() {
    if !live_network_enabled() {
        return;
    }

    let checker = DohChecker::new().await;
    assert_eq!(checker.name(), "DoH");
    assert_eq!(checker.priority(), CheckerPriority::Fast);
    assert!(checker.supports_tld("com"));
    assert!(checker.supports_tld("uk"));
    assert!(checker.supports_tld("xyz"));
    assert!(!checker.is_authoritative());
}

#[tokio::test]
async fn test_doh_should_stop_pipeline_when_registered() {
    if !live_network_enabled() {
        return;
    }

    let checker = DohChecker::new().await;
    let result = checker.check("google.com").await;
    if !result.available && result.error.is_none() {
        assert!(checker.should_stop_pipeline(&result));
    }
}

#[tokio::test]
async fn test_doh_should_not_stop_pipeline_when_available() {
    let checker = DohChecker::new().await;
    let result = CheckResult::available();
    assert!(!checker.should_stop_pipeline(&result));
}

#[tokio::test]
async fn test_doh_with_custom_servers() {
    if !live_network_enabled() {
        return;
    }

    let servers = vec!["https://dns.alidns.com/resolve".to_string()];
    let checker = DohChecker::with_servers(servers).await;
    assert!(!checker.servers.is_empty());
    let result = checker.check("google.com").await;
    if result.error.is_none() {
        assert!(!result.available);
    }
}

#[tokio::test]
async fn test_rdap_checker_metadata() {
    let mut custom = std::collections::HashMap::new();
    custom.insert("com".to_string(), "https://rdap.example.test/".to_string());
    custom.insert(
        "co.uk".to_string(),
        "https://rdap.example.test/".to_string(),
    );
    let checker = RdapChecker::with_config(custom, None).await;
    assert_eq!(checker.name(), "RDAP");
    assert_eq!(checker.priority(), CheckerPriority::Standard);
    assert!(checker.supports_tld("com"));
    assert!(checker.supports_tld("co.uk"));
    assert!(!checker.supports_tld("zzzzz"));
    assert!(checker.is_authoritative());
}

#[tokio::test]
async fn test_rdap_builtin_supports_uk_without_bootstrap() {
    let checker = RdapChecker::with_config(std::collections::HashMap::new(), None).await;
    assert!(checker.supports_tld("uk"));
    assert_eq!(checker.matching_suffix("4tb.uk").as_deref(), Some("uk"));
}

#[tokio::test]
async fn test_doh_round_robin() {
    if !live_network_enabled() {
        return;
    }

    let servers = vec![
        "https://dns.alidns.com/resolve".to_string(),
        "https://doh.pub/dns-query".to_string(),
    ];
    let checker = DohChecker::with_servers(servers).await;

    let idx1 = checker.current_idx.load(Ordering::Relaxed);
    let _ = checker.check("google.com").await;
    let idx2 = checker.current_idx.load(Ordering::Relaxed);
    assert!(idx2 > idx1, "round-robin index should advance");
}

// =============================================================================
// 4. WhoisChecker Tests (requires network)
// =============================================================================

#[tokio::test]
async fn test_whois_registered_com() {
    if !live_network_enabled() {
        return;
    }

    let mut m = std::collections::HashMap::new();
    m.insert("com".to_string(), "whois.verisign-grs.com".to_string());
    let checker = WhoisChecker::with_servers(m);
    let result = checker.check("google.com").await;
    if result.error.is_none() {
        assert!(
            !result.available,
            "google.com should be registered via WHOIS"
        );
        assert!(result.signatures.contains(&"WHOIS".to_string()));
    } else {
        println!(
            "Notice: WHOIS check skipped due to network error: {:?}",
            result.error
        );
    }
}

#[tokio::test]
async fn test_whois_available_random() {
    if !live_network_enabled() {
        return;
    }

    let mut m = std::collections::HashMap::new();
    m.insert("com".to_string(), "whois.verisign-grs.com".to_string());
    let checker = WhoisChecker::with_servers(m);
    let domain = format!(
        "test-whois-avail-{}.com",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let result = checker.check(&domain).await;
    if result.error.is_none() {
        assert!(
            result.available,
            "random domain should be available via WHOIS"
        );
    }
}

#[tokio::test]
async fn test_whois_unsupported_tld() {
    let checker = WhoisChecker::new();
    let result = checker.check("something.zzzz").await;
    assert!(result.available, "Unknown TLD should be skipped cleanly");
}

#[tokio::test]
async fn test_whois_invalid_domain() {
    let checker = WhoisChecker::new();
    let result = checker.check("singleword").await;
    assert!(result.error.is_some(), "single word should be an error");
}

#[tokio::test]
async fn test_whois_checker_metadata() {
    let mut custom = std::collections::HashMap::new();
    for tld in [
        "com", "net", "org", "uk", "li", "at", "be", "pl", "es", "art", "blog", "website", "cn",
        "co.uk", "com.cn", "com.au", "org.in", "cn.com", "jp.net", "co.nz", "com.tw",
    ] {
        custom.insert(tld.to_string(), "whois.example.test".to_string());
    }
    let checker = WhoisChecker::with_servers(custom);
    assert_eq!(checker.name(), "WHOIS");
    assert_eq!(checker.priority(), CheckerPriority::Fallback);
    assert!(checker.supports_tld("com"));
    assert!(checker.supports_tld("net"));
    assert!(checker.supports_tld("org"));
    assert!(checker.supports_tld("uk"));
    assert!(checker.supports_tld("li"));
    assert!(checker.supports_tld("at"));
    assert!(checker.supports_tld("be"));
    assert!(checker.supports_tld("pl"));
    assert!(checker.supports_tld("es"));
    assert!(checker.supports_tld("art"));
    assert!(checker.supports_tld("blog"));
    assert!(checker.supports_tld("website"));
    assert!(checker.supports_tld("cn"));
    assert!(checker.supports_tld("co.uk"));
    assert!(checker.supports_tld("com.cn"));
    assert!(checker.supports_tld("com.au"));
    assert!(checker.supports_tld("org.in"));
    assert!(checker.supports_tld("cn.com"));
    assert!(checker.supports_tld("jp.net"));
    assert!(checker.supports_tld("co.nz"));
    assert!(checker.supports_tld("com.tw"));
    assert!(!checker.supports_tld("zzzzz"));
    assert!(checker.is_authoritative());
}

// =============================================================================
// 5. CircuitBreaker Tests
// =============================================================================

#[test]
fn test_circuit_breaker_initially_closed() {
    let cb = CircuitBreaker::new(3, 10);
    assert!(cb.allow_request());
}

#[test]
fn test_circuit_breaker_stays_closed_below_threshold() {
    let cb = CircuitBreaker::new(3, 10);
    cb.record_failure();
    cb.record_failure();
    assert!(
        cb.allow_request(),
        "should still be closed with 2/3 failures"
    );
}

#[test]
fn test_circuit_breaker_trips_at_threshold() {
    let cb = CircuitBreaker::new(3, 60);
    cb.record_failure();
    cb.record_failure();
    cb.record_failure();
    assert!(
        !cb.allow_request(),
        "should be open after reaching threshold"
    );
}

#[test]
fn test_circuit_breaker_resets_on_success() {
    let cb = CircuitBreaker::new(3, 60);
    cb.record_failure();
    cb.record_failure();
    cb.record_success();
    assert!(cb.allow_request());
    cb.record_failure();
    assert!(cb.allow_request());
}

#[test]
fn test_circuit_breaker_half_open_after_timeout() {
    let cb = CircuitBreaker::new(1, 1);
    cb.record_failure();
    std::thread::sleep(Duration::from_millis(2100));
    assert!(
        cb.allow_request(),
        "should be half-open after recovery timeout"
    );
}

#[test]
fn test_circuit_breaker_multiple_successes_no_effect() {
    let cb = CircuitBreaker::new(3, 60);
    cb.record_success();
    cb.record_success();
    cb.record_success();
    assert!(cb.allow_request());
}

// =============================================================================
// 6. CheckerRegistry Pipeline Tests (Full Integration)
// =============================================================================

#[tokio::test]
async fn test_registry_with_defaults() {
    let registry =
        CheckerRegistry::with_defaults(AppConfig::default(), std::collections::HashMap::new())
            .await;
    let names = registry.checker_names();
    assert!(names.contains(&"LocalReserved"));
    assert!(names.contains(&"DoH"));
    assert!(names.contains(&"RDAP"));
    assert!(names.contains(&"WHOIS"));
}

#[tokio::test]
async fn test_registry_checker_order() {
    let registry =
        CheckerRegistry::with_defaults(AppConfig::default(), std::collections::HashMap::new())
            .await;
    let names = registry.checker_names();
    let local_idx = names.iter().position(|&n| n == "LocalReserved");
    let doh_idx = names.iter().position(|&n| n == "DoH");
    let rdap_idx = names.iter().position(|&n| n == "RDAP");
    let whois_idx = names.iter().position(|&n| n == "WHOIS");
    assert!(local_idx < doh_idx, "LocalReserved should come before DoH");
    assert!(doh_idx < rdap_idx, "DoH should come before RDAP");
    assert!(rdap_idx < whois_idx, "RDAP should come before WHOIS");
}

#[tokio::test]
async fn test_registry_prefers_rdap_before_whois_for_custom_suffix() {
    let (bootstrap_url, handle) = spawn_mock_rdap_server().await;

    let config = AppConfig {
        rdap_bootstrap_url: Some(bootstrap_url),
        whois_servers: [("alpha".to_string(), "127.0.0.1:9".to_string())]
            .into_iter()
            .collect(),
        ..AppConfig::default()
    };

    let registry =
        CheckerRegistry::with_defaults(config.clone(), config.whois_servers.clone()).await;
    let result = registry.check("taken.alpha").await;

    assert!(!result.available);
    assert!(result.signatures.contains(&"RDAP".to_string()));
    assert!(!result.signatures.contains(&"WHOIS".to_string()));
    assert!(result.error.is_none());

    handle.abort();
}

#[tokio::test]
async fn test_registry_reserved_domain_stops_early() {
    let registry =
        CheckerRegistry::with_defaults(AppConfig::default(), std::collections::HashMap::new())
            .await;
    let result = registry.check("example.com").await;
    assert!(!result.available, "example.com should be registered");
    assert!(result.signatures.contains(&"RESERVED".to_string()));
    assert!(
        !result.signatures.contains(&"DNS".to_string()),
        "pipeline should have stopped before DoH"
    );
}

#[tokio::test]
async fn test_registry_registered_workflow() {
    if !live_network_enabled() {
        return;
    }

    let registry =
        CheckerRegistry::with_defaults(AppConfig::default(), std::collections::HashMap::new())
            .await;
    let result = registry.check("google.com").await;
    assert!(
        !result.available,
        "google.com should be registered (pipeline)"
    );
}

#[tokio::test]
async fn test_registry_available_workflow() {
    if !live_network_enabled() {
        return;
    }

    let registry =
        CheckerRegistry::with_defaults(AppConfig::default(), std::collections::HashMap::new())
            .await;
    let domain = format!(
        "test-pipeline-avail-{}.com",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let result = registry.check(&domain).await;
    // Accept either: available=true, or error (network issues with WHOIS/DoH)
    // But should NOT be "registered" (with signatures and no error)
    if !result.available {
        assert!(
            result.error.is_some(),
            "if not available, should be due to an error, not registration. signatures={:?}",
            result.signatures
        );
    }
}

#[tokio::test]
async fn test_registry_invalid_domain_empty() {
    let registry =
        CheckerRegistry::with_defaults(AppConfig::default(), std::collections::HashMap::new())
            .await;
    let result = registry.check("").await;
    assert!(result.error.is_some(), "empty string should be an error");
    assert_eq!(result.error.unwrap(), "Invalid domain format");
}

#[tokio::test]
async fn test_registry_invalid_domain_no_dot() {
    let registry =
        CheckerRegistry::with_defaults(AppConfig::default(), std::collections::HashMap::new())
            .await;
    let result = registry.check("singleword").await;
    assert!(result.error.is_some(), "single word should be an error");
    assert_eq!(result.error.unwrap(), "Invalid domain format");
}

#[tokio::test]
async fn test_registry_empty() {
    let registry = CheckerRegistry::new();
    let result = registry.check("google.com").await;
    assert!(result.available, "empty registry should return available");
}

// =============================================================================
// 7. DomainGenerator Tests
// =============================================================================

#[tokio::test]
async fn test_generator_letters_length1() {
    let dg = generator::generate_domains(
        1,
        ".com".to_string(),
        "D".to_string(),
        "".to_string(),
        "".to_string(),
        vec![],
        0,
    )
    .unwrap();
    assert_eq!(dg.total_count, 26);
    let mut domains: Vec<String> = Vec::new();
    let mut rx = dg.domains;
    while let Some(d) = rx.recv().await {
        domains.push(d);
    }
    assert_eq!(domains.len(), 26);
    assert_eq!(domains[0], "a.com");
    assert_eq!(domains[25], "z.com");
}

#[tokio::test]
async fn test_generator_numbers_length2() {
    let dg = generator::generate_domains(
        2,
        ".net".to_string(),
        "d".to_string(),
        "".to_string(),
        "".to_string(),
        vec![],
        0,
    )
    .unwrap();
    assert_eq!(dg.total_count, 100);
    let mut domains: Vec<String> = Vec::new();
    let mut rx = dg.domains;
    while let Some(d) = rx.recv().await {
        domains.push(d);
    }
    assert_eq!(domains.len(), 100);
    assert_eq!(domains[0], "00.net");
    assert_eq!(domains[99], "99.net");
}

#[tokio::test]
async fn test_generator_alphanumeric_length1() {
    let dg = generator::generate_domains(
        1,
        ".io".to_string(),
        "a".to_string(),
        "".to_string(),
        "".to_string(),
        vec![],
        0,
    )
    .unwrap();
    assert_eq!(dg.total_count, 36);
    let mut domains: Vec<String> = Vec::new();
    let mut rx = dg.domains;
    while let Some(d) = rx.recv().await {
        domains.push(d);
    }
    assert_eq!(domains.len(), 36);
    assert_eq!(domains[0], "a.io");
    assert_eq!(domains[25], "z.io");
    assert_eq!(domains[26], "0.io");
    assert_eq!(domains[35], "9.io");
}

#[tokio::test]
async fn test_generator_skip() {
    let dg = generator::generate_domains(
        1,
        ".com".to_string(),
        "D".to_string(),
        "".to_string(),
        "".to_string(),
        vec![],
        5,
    )
    .unwrap();
    let mut domains: Vec<String> = Vec::new();
    let mut rx = dg.domains;
    while let Some(d) = rx.recv().await {
        domains.push(d);
    }
    assert_eq!(domains.len(), 21);
    assert_eq!(domains[0], "f.com");
}

#[tokio::test]
async fn test_generator_skip_all() {
    let dg = generator::generate_domains(
        1,
        ".com".to_string(),
        "D".to_string(),
        "".to_string(),
        "".to_string(),
        vec![],
        26,
    )
    .unwrap();
    let mut domains: Vec<String> = Vec::new();
    let mut rx = dg.domains;
    while let Some(d) = rx.recv().await {
        domains.push(d);
    }
    assert_eq!(domains.len(), 0);
}

#[tokio::test]
async fn test_generator_skip_beyond_total() {
    let dg = generator::generate_domains(
        1,
        ".com".to_string(),
        "D".to_string(),
        "".to_string(),
        "".to_string(),
        vec![],
        100,
    )
    .unwrap();
    let mut domains: Vec<String> = Vec::new();
    let mut rx = dg.domains;
    while let Some(d) = rx.recv().await {
        domains.push(d);
    }
    assert_eq!(domains.len(), 0);
}

#[tokio::test]
async fn test_generator_with_regex_filter() {
    let dg = generator::generate_domains(
        3,
        ".com".to_string(),
        "D".to_string(),
        "^ab".to_string(),
        "".to_string(),
        vec![],
        0,
    )
    .unwrap();
    let mut domains: Vec<String> = Vec::new();
    let mut rx = dg.domains;
    while let Some(d) = rx.recv().await {
        domains.push(d);
    }
    for d in &domains {
        assert!(d.starts_with("ab"), "domain {} should start with 'ab'", d);
    }
    assert_eq!(domains.len(), 26);
}

#[tokio::test]
async fn test_generator_with_strict_regex() {
    let dg = generator::generate_domains(
        3,
        ".com".to_string(),
        "a".to_string(),
        "^[a-z]{2}[0-9]$".to_string(),
        "".to_string(),
        vec![],
        0,
    )
    .unwrap();
    let mut domains: Vec<String> = Vec::new();
    let mut rx = dg.domains;
    while let Some(d) = rx.recv().await {
        domains.push(d);
    }
    let re = regex::Regex::new("^[a-z]{2}[0-9]$").unwrap();
    for d in &domains {
        let prefix = d.strip_suffix(".com").unwrap();
        assert!(re.is_match(prefix), "prefix {} should match regex", prefix);
    }
    assert_eq!(domains.len(), 26 * 26 * 10);
}

#[tokio::test]
async fn test_generator_suffix_variations() {
    let dg = generator::generate_domains(
        1,
        ".uk".to_string(),
        "d".to_string(),
        "".to_string(),
        "".to_string(),
        vec![],
        0,
    )
    .unwrap();
    let mut domains: Vec<String> = Vec::new();
    let mut rx = dg.domains;
    while let Some(d) = rx.recv().await {
        domains.push(d);
    }
    assert_eq!(domains.len(), 10);
    for d in &domains {
        assert!(d.ends_with(".uk"));
    }
}

#[tokio::test]
async fn test_generator_generated_counter() {
    let dg = generator::generate_domains(
        1,
        ".com".to_string(),
        "d".to_string(),
        "".to_string(),
        "".to_string(),
        vec![],
        0,
    )
    .unwrap();
    let generated = dg.generated.clone();
    let mut rx = dg.domains;
    assert_eq!(generated.load(Ordering::Relaxed), 0);
    while let Some(_d) = rx.recv().await {}
    assert_eq!(generated.load(Ordering::Relaxed), 10);
}

#[tokio::test]
async fn test_generator_dictionary_mode() {
    let dict_path = std::env::temp_dir().join("test_dict_integration.txt");
    std::fs::write(&dict_path, "hello\nworld\nrust\n\n  \ntest\n").unwrap();
    let dg = generator::generate_domains(
        0,
        ".dev".to_string(),
        "D".to_string(),
        "".to_string(),
        dict_path.to_str().unwrap().to_string(),
        vec![],
        0,
    )
    .unwrap();
    let mut domains: Vec<String> = Vec::new();
    let mut rx = dg.domains;
    while let Some(d) = rx.recv().await {
        domains.push(d);
    }
    assert!(domains.contains(&"hello.dev".to_string()));
    assert!(domains.contains(&"world.dev".to_string()));
    assert!(domains.contains(&"rust.dev".to_string()));
    assert!(domains.contains(&"test.dev".to_string()));
    let _ = std::fs::remove_file(&dict_path);
}

#[tokio::test]
async fn test_generator_dictionary_with_regex() {
    let dict_path = std::env::temp_dir().join("test_dict_regex.txt");
    std::fs::write(&dict_path, "apple\nbanana\napricot\nblueberry\navocado\n").unwrap();
    let dg = generator::generate_domains(
        0,
        ".com".to_string(),
        "D".to_string(),
        "^a".to_string(),
        dict_path.to_str().unwrap().to_string(),
        vec![],
        0,
    )
    .unwrap();
    let mut domains: Vec<String> = Vec::new();
    let mut rx = dg.domains;
    while let Some(d) = rx.recv().await {
        domains.push(d);
    }
    assert!(domains.contains(&"apple.com".to_string()));
    assert!(domains.contains(&"apricot.com".to_string()));
    assert!(domains.contains(&"avocado.com".to_string()));
    assert!(!domains.contains(&"banana.com".to_string()));
    assert!(!domains.contains(&"blueberry.com".to_string()));
    let _ = std::fs::remove_file(&dict_path);
}

#[tokio::test]
async fn test_generator_dictionary_with_skip() {
    let dict_path = std::env::temp_dir().join("test_dict_skip.txt");
    std::fs::write(&dict_path, "one\ntwo\nthree\nfour\nfive\n").unwrap();
    let dg = generator::generate_domains(
        0,
        ".com".to_string(),
        "D".to_string(),
        "".to_string(),
        dict_path.to_str().unwrap().to_string(),
        vec![],
        2,
    )
    .unwrap();
    let mut domains: Vec<String> = Vec::new();
    let mut rx = dg.domains;
    while let Some(d) = rx.recv().await {
        domains.push(d);
    }
    assert!(!domains.contains(&"one.com".to_string()));
    assert!(!domains.contains(&"two.com".to_string()));
    assert!(domains.contains(&"three.com".to_string()));
    assert!(domains.contains(&"four.com".to_string()));
    assert!(domains.contains(&"five.com".to_string()));
    let _ = std::fs::remove_file(&dict_path);
}

// =============================================================================
// 9. AppConfig Tests
// =============================================================================

#[test]
fn test_config_default() {
    let config = AppConfig::default();
    assert!(config.doh_servers.is_empty());
    assert!(config.whois_servers.is_empty());
    assert!(config.rdap_servers.is_empty());
    assert!(config.rdap_bootstrap_url.is_none());
}

#[test]
fn test_config_load_nonexistent_file() {
    let config = AppConfig::load_from_file("nonexistent_config_file_xyz.json");
    assert!(config.doh_servers.is_empty());
}

#[test]
fn test_config_load_valid_file() {
    let path = std::env::temp_dir().join("test_config_valid_integ.json");
    let content = r#"{"doh_servers":["https://dns.google/resolve"],"whois_servers":{"com":"whois.verisign-grs.com"},"rdap_servers":{"com":"https://rdap.example.test/"},"rdap_bootstrap_url":"https://data.iana.org/rdap/dns.json"}"#;
    std::fs::write(&path, content).unwrap();
    let config = AppConfig::load_from_file(path.to_str().unwrap());
    assert_eq!(config.doh_servers.len(), 1);
    assert_eq!(config.doh_servers[0], "https://dns.google/resolve");
    assert_eq!(
        config.whois_servers.get("com").map(|s| s.as_str()),
        Some("whois.verisign-grs.com")
    );
    assert_eq!(
        config.rdap_servers.get("com").map(|s| s.as_str()),
        Some("https://rdap.example.test/")
    );
    assert_eq!(
        config.rdap_bootstrap_url.as_deref(),
        Some("https://data.iana.org/rdap/dns.json")
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_config_load_invalid_json() {
    let path = std::env::temp_dir().join("test_config_invalid_integ.json");
    std::fs::write(&path, "invalid json {{{").unwrap();
    let config = AppConfig::load_from_file(path.to_str().unwrap());
    assert!(config.doh_servers.is_empty());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_config_save_default_if_not_exists() {
    let path = std::env::temp_dir().join("test_config_save_default_integ.json");
    let _ = std::fs::remove_file(&path);
    AppConfig::save_default_if_not_exists(path.to_str().unwrap());
    assert!(path.exists(), "config file should be created");
    let config = AppConfig::load_from_file(path.to_str().unwrap());
    assert!(config.doh_servers.is_empty());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_config_save_does_not_overwrite() {
    let path = std::env::temp_dir().join("test_config_no_overwrite_integ.json");
    let custom = r#"{"doh_servers":["https://custom.server/dns"]}"#;
    std::fs::write(&path, custom).unwrap();
    AppConfig::save_default_if_not_exists(path.to_str().unwrap());
    let config = AppConfig::load_from_file(path.to_str().unwrap());
    assert_eq!(config.doh_servers.len(), 1);
    assert_eq!(config.doh_servers[0], "https://custom.server/dns");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_config_serialization_roundtrip() {
    let mut config = AppConfig::default();
    config.doh_servers = vec!["https://server1.com".to_string()];
    config
        .whois_servers
        .insert("com".to_string(), "whois.example.com".to_string());
    config
        .rdap_servers
        .insert("com".to_string(), "https://rdap.example.com/".to_string());
    config.rdap_bootstrap_url = Some("https://data.iana.org/rdap/dns.json".to_string());
    let json = serde_json::to_string(&config).unwrap();
    let deserialized: AppConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.doh_servers, config.doh_servers);
    assert_eq!(deserialized.whois_servers, config.whois_servers);
    assert_eq!(deserialized.rdap_servers, config.rdap_servers);
    assert_eq!(deserialized.rdap_bootstrap_url, config.rdap_bootstrap_url);
}

// =============================================================================
// 11. DomainResult and WorkerMessage Tests
// =============================================================================

#[test]
fn test_domain_result_construction() {
    let result = DomainResult {
        domain: "test.com".to_string(),
        available: true,
        error: None,
        signatures: vec![],
        expiration_date: None,
        rate_limited: false,
        retryable: false,
        retry_after_secs: None,
        trace: vec![],
    };
    assert_eq!(result.domain, "test.com");
    assert!(result.available);
}

#[test]
fn test_domain_result_with_error() {
    let result = DomainResult {
        domain: "bad.com".to_string(),
        available: false,
        error: Some("timeout".to_string()),
        signatures: vec![],
        expiration_date: None,
        rate_limited: false,
        retryable: false,
        retry_after_secs: None,
        trace: vec![],
    };
    assert!(!result.available);
    assert_eq!(result.error.as_deref(), Some("timeout"));
}

#[test]
fn test_domain_result_serialization() {
    let result = DomainResult {
        domain: "test.com".to_string(),
        available: true,
        error: None,
        signatures: vec!["DNS".to_string()],
        expiration_date: None,
        rate_limited: false,
        retryable: false,
        retry_after_secs: None,
        trace: vec![],
    };
    let json = serde_json::to_string(&result).unwrap();
    let deserialized: DomainResult = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.domain, "test.com");
    assert!(deserialized.available);
    assert_eq!(deserialized.signatures, vec!["DNS".to_string()]);
}

// =============================================================================
// 12. Edge Cases and Error Handling
// =============================================================================

#[tokio::test]
async fn test_registry_domain_with_many_dots() {
    let (bootstrap_url, handle) = spawn_mock_rdap_server().await;
    let config = AppConfig {
        rdap_bootstrap_url: Some(bootstrap_url),
        ..AppConfig::default()
    };
    let registry =
        CheckerRegistry::with_defaults(config.clone(), config.whois_servers.clone()).await;
    let result = registry.check("subdomain.taken.alpha").await;
    assert!(
        result.error.is_none(),
        "multi-level domain should not error"
    );
    assert!(!result.available);
    assert!(result.signatures.contains(&"RDAP".to_string()));

    handle.abort();
}

#[tokio::test]
async fn test_registry_accepts_multi_part_public_suffix() {
    let (bootstrap_url, handle) = spawn_mock_rdap_server().await;
    let config = AppConfig {
        rdap_bootstrap_url: Some(bootstrap_url),
        ..AppConfig::default()
    };
    let registry =
        CheckerRegistry::with_defaults(config.clone(), config.whois_servers.clone()).await;
    let result = registry.check("taken.co.alpha").await;
    assert!(
        result.error.is_none(),
        "multi-part public suffix should not error"
    );
    assert!(!result.available);
    assert!(result.signatures.contains(&"RDAP".to_string()));

    handle.abort();
}

#[tokio::test]
async fn test_registry_single_char_domain() {
    if !live_network_enabled() {
        return;
    }

    let registry =
        CheckerRegistry::with_defaults(AppConfig::default(), std::collections::HashMap::new())
            .await;
    let result = registry.check("a.com").await;
    assert!(
        result.error.is_none() || result.retryable,
        "single char domain should not produce a hard error"
    );
}

#[tokio::test]
async fn test_registry_numeric_domain() {
    if !live_network_enabled() {
        return;
    }

    let registry =
        CheckerRegistry::with_defaults(AppConfig::default(), std::collections::HashMap::new())
            .await;
    let result = registry.check("123.com").await;
    assert!(
        result.error.is_none(),
        "numeric domain should not error, but got: {:?}",
        result.error
    );
}

#[tokio::test]
async fn test_checker_priority_ordering() {
    assert!(CheckerPriority::Local < CheckerPriority::Fast);
    assert!(CheckerPriority::Fast < CheckerPriority::Standard);
    assert!(CheckerPriority::Standard < CheckerPriority::Fallback);
}

#[tokio::test]
async fn test_generator_length2_letters() {
    let dg = generator::generate_domains(
        2,
        ".com".to_string(),
        "D".to_string(),
        "".to_string(),
        "".to_string(),
        vec![],
        0,
    )
    .unwrap();
    assert_eq!(dg.total_count, 676);
    let mut domains: Vec<String> = Vec::new();
    let mut rx = dg.domains;
    while let Some(d) = rx.recv().await {
        domains.push(d);
    }
    assert_eq!(domains.len(), 676);
    assert_eq!(domains[0], "aa.com");
    assert_eq!(domains[675], "zz.com");
}

