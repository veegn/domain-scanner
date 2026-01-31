use crate::DomainResult;
use crate::checker::{CheckResult, CheckerRegistry};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::sync::mpsc;

pub async fn worker(
    _id: usize,
    jobs: Arc<Mutex<mpsc::Receiver<String>>>,
    results: mpsc::Sender<DomainResult>,
    delay: Duration,
    registry: Arc<CheckerRegistry>,
) {
    loop {
        // Lock the receiver just long enough to get a job
        let domain_name = {
            let mut rx = jobs.lock().await;
            rx.recv().await
        };

        match domain_name {
            Some(domain) => {
                // Use the registry to check the domain
                let check_result: CheckResult = registry.check(&domain).await;

                let result = DomainResult {
                    domain,
                    available: check_result.available,
                    error: check_result.error,
                    signatures: check_result.signatures,
                };

                if results.send(result).await.is_err() {
                    break;
                }

                tokio::time::sleep(delay).await;
            }
            None => break, // Channel closed and empty
        }
    }
}
