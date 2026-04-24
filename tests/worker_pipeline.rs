use async_channel::bounded;
use domain_scanner::checker::CheckerRegistry;
use domain_scanner::config::AppConfig;
use domain_scanner::generator;
use domain_scanner::web::models::TaskSignal;
use domain_scanner::worker;
use domain_scanner::{DomainResult, WorkerMessage};
use std::sync::Arc;
use std::sync::atomic::AtomicU8;
use std::time::Duration;
use tokio::sync::mpsc;

fn live_network_enabled() -> bool {
    std::env::var("DOMAIN_SCANNER_LIVE_TESTS")
        .map(|v| v == "1")
        .unwrap_or(false)
}

#[tokio::test]
async fn test_worker_processes_domains() {
    let registry = Arc::new(
        CheckerRegistry::with_defaults(AppConfig::default(), std::collections::HashMap::new())
            .await,
    );
    let (job_tx, job_rx) = bounded(10);
    let (result_tx, mut result_rx) = mpsc::channel(10);
    let reg_clone = registry.clone();
    let cancel_flag = Arc::new(AtomicU8::new(TaskSignal::Run as u8));
    let throttle = Arc::new(worker::WorkerThrottle::new(Duration::from_millis(0), 1));
    tokio::spawn(async move {
        worker::worker(1, job_rx, result_tx, throttle, reg_clone, cancel_flag).await;
    });
    job_tx.send("google.com".to_string()).await.unwrap();
    drop(job_tx);
    let mut messages = Vec::new();
    while let Some(msg) = result_rx.recv().await {
        messages.push(msg);
    }
    let has_scanning = messages
        .iter()
        .any(|m| matches!(m, WorkerMessage::Scanning(d) if d == "google.com"));
    let has_result = messages
        .iter()
        .any(|m| matches!(m, WorkerMessage::Result(r) if r.domain == "google.com"));
    assert!(has_scanning, "should have a Scanning message");
    assert!(has_result, "should have a Result message");
}

#[tokio::test]
async fn test_worker_multiple_domains() {
    let registry = Arc::new(
        CheckerRegistry::with_defaults(AppConfig::default(), std::collections::HashMap::new())
            .await,
    );
    let (job_tx, job_rx) = bounded(10);
    let (result_tx, mut result_rx) = mpsc::channel(100);
    let reg_clone = registry.clone();
    let cancel_flag = Arc::new(AtomicU8::new(TaskSignal::Run as u8));
    let throttle = Arc::new(worker::WorkerThrottle::new(Duration::from_millis(0), 1));
    tokio::spawn(async move {
        worker::worker(1, job_rx, result_tx, throttle, reg_clone, cancel_flag).await;
    });
    let test_domains = vec!["example.com".to_string(), "test.org".to_string()];
    for d in &test_domains {
        job_tx.send(d.clone()).await.unwrap();
    }
    drop(job_tx);
    let mut results: Vec<DomainResult> = Vec::new();
    while let Some(msg) = result_rx.recv().await {
        if let WorkerMessage::Result(r) = msg {
            results.push(r);
        }
    }
    assert_eq!(results.len(), 2);
    for r in &results {
        assert!(!r.available, "{} should be registered", r.domain);
    }
}

#[tokio::test]
async fn test_worker_multiple_workers_share_jobs() {
    let registry = Arc::new(
        CheckerRegistry::with_defaults(AppConfig::default(), std::collections::HashMap::new())
            .await,
    );
    let (job_tx, job_rx) = bounded(100);
    let (result_tx, mut result_rx) = mpsc::channel(100);
    let throttle = Arc::new(worker::WorkerThrottle::new(Duration::from_millis(0), 3));
    for id in 1..=3 {
        let jobs_clone = job_rx.clone();
        let tx_clone = result_tx.clone();
        let reg_clone = registry.clone();
        let cancel_flag = Arc::new(AtomicU8::new(TaskSignal::Run as u8));
        let throttle_clone = throttle.clone();
        tokio::spawn(async move {
            worker::worker(
                id,
                jobs_clone,
                tx_clone,
                throttle_clone,
                reg_clone,
                cancel_flag,
            )
            .await;
        });
    }
    drop(result_tx);
    let reserved_domains = vec![
        "example.com",
        "test.org",
        "invalid.net",
        "localhost",
        "www.com",
        "nic.uk",
    ];
    for d in &reserved_domains {
        job_tx.send(d.to_string()).await.unwrap();
    }
    drop(job_tx);
    let mut domain_results: Vec<DomainResult> = Vec::new();
    while let Some(msg) = result_rx.recv().await {
        if let WorkerMessage::Result(r) = msg {
            domain_results.push(r);
        }
    }
    assert_eq!(
        domain_results.len(),
        reserved_domains.len(),
        "all domains should be processed"
    );
}

#[tokio::test]
async fn test_full_pipeline_with_generator_and_worker() {
    if !live_network_enabled() {
        return;
    }

    let registry = Arc::new(
        CheckerRegistry::with_defaults(AppConfig::default(), std::collections::HashMap::new())
            .await,
    );
    let dg = generator::generate_domains(
        1,
        ".zzzztest".to_string(),
        "d".to_string(),
        "".to_string(),
        "".to_string(),
        vec![],
        0,
    )
    .unwrap();
    let (result_tx, mut result_rx) = mpsc::channel(100);
    let (job_tx, job_rx) = bounded(100);
    tokio::spawn(async move {
        let mut domains = dg.domains;
        while let Some(domain) = domains.recv().await {
            if job_tx.send(domain).await.is_err() {
                break;
            }
        }
    });
    let reg_clone = registry.clone();
    let cancel_flag = Arc::new(AtomicU8::new(TaskSignal::Run as u8));
    let throttle = Arc::new(worker::WorkerThrottle::new(Duration::from_millis(0), 1));
    tokio::spawn(async move {
        worker::worker(1, job_rx, result_tx, throttle, reg_clone, cancel_flag).await;
    });
    let mut scan_count = 0u32;
    let mut result_count = 0u32;
    while let Some(msg) = result_rx.recv().await {
        match msg {
            WorkerMessage::Scanning(_) => scan_count += 1,
            WorkerMessage::Result(_) => result_count += 1,
        }
    }
    assert_eq!(scan_count, 10, "should scan exactly 10 domains");
    assert_eq!(result_count, 10, "should produce 10 results");
}
