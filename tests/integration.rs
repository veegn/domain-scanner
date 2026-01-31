use domain_scanner::checker::{DohChecker, DomainChecker, LocalReservedChecker, RdapChecker};

#[tokio::test]
async fn test_local_reserved() {
    let checker = LocalReservedChecker::new();
    let result = checker.check("google.com").await;
    assert!(!result.available, "google.com should be reserved");
}

#[tokio::test]
async fn test_doh_google() {
    let checker = DohChecker::new();
    let result = checker.check("google.com").await;
    assert!(!result.available);
}

#[tokio::test]
async fn test_rdap_google() {
    let checker = RdapChecker::new();
    let result = checker.check("google.com").await;
    assert!(!result.available);
}
// Basic stable TLD tests
#[tokio::test]
async fn test_rdap_net() {
    let checker = RdapChecker::new();
    // example.net is reserved/registered
    let result = checker.check("example.net").await;
    assert!(!result.available, "example.net should be registered");
}

#[tokio::test]
async fn test_rdap_io() {
    let checker = RdapChecker::new();
    let result = checker.check("nic.io").await;
    if let Some(err) = result.error {
        println!("Notice: nic.io check failed: {:?}", err);
    } else {
        assert!(!result.available, "nic.io should be registered");
    }
}

// More exotic TLDs (might be slower or rate limited)
#[tokio::test]
async fn test_rdap_li() {
    let checker = RdapChecker::new();
    let result = checker.check("nic.li").await;

    // .li registry can be unstable
    if let Some(err) = result.error {
        println!("Notice: nic.li check failed: {:?}", err);
    } else {
        assert!(!result.available, "nic.li should be registered");
    }
}

#[tokio::test]
async fn test_rdap_xyz() {
    let checker = RdapChecker::new();
    // nic.xyz is the registry
    let result = checker.check("nic.xyz").await;

    if let Some(err) = result.error {
        println!("Notice: nic.xyz check failed: {:?}", err);
    } else {
        assert!(!result.available, "nic.xyz should be registered");
    }
}

#[tokio::test]
async fn test_rdap_available_random() {
    // Generate a random domain unlikely to exist
    let checker = RdapChecker::new();
    let domain = format!(
        "test-rdap-available-{}.com",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let result = checker.check(&domain).await;

    // Should be available
    assert!(result.available, "random com domain should be available");
}

#[tokio::test]
async fn test_rdap_us() {
    let checker = RdapChecker::new();
    let result = checker.check("aaa.us").await;
    assert!(!result.available, "aaa.us should be registered");
}
