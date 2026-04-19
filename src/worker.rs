use crate::DomainResult;
use crate::checker::{CheckResult, CheckerRegistry};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::sync::mpsc;

pub async fn worker(
    id: usize,
    jobs: Arc<Mutex<mpsc::Receiver<String>>>,
    results: mpsc::Sender<crate::WorkerMessage>,
    delay: Duration,
    registry: Arc<CheckerRegistry>,
    stop_signal: Arc<AtomicU8>,
) {
    println!("Worker {} started", id);
    loop {
        if stop_signal.load(Ordering::Relaxed) != 0 {
            println!("Worker {} stopping due to task signal", id);
            break;
        }

        // Lock the receiver just long enough to get a job
        let domain_name = {
            let mut rx = jobs.lock().await;
            rx.recv().await
        };

        match domain_name {
            Some(domain) => {
                // Notify scanning
                if results
                    .send(crate::WorkerMessage::Scanning(domain.clone()))
                    .await
                    .is_err()
                {
                    eprintln!(
                        "Worker {} failed to publish scanning event because result channel closed",
                        id
                    );
                    break;
                }

                // Use the registry to check the domain
                let check_result: CheckResult = registry.check(&domain).await;

                let result = DomainResult {
                    domain,
                    available: check_result.available,
                    error: check_result.error,
                    signatures: check_result.signatures,
                    expiration_date: check_result.expiration_date,
                    rate_limited: check_result.rate_limited,
                    retryable: check_result.retryable,
                    retry_after_secs: check_result.retry_after_secs,
                    trace: check_result.trace,
                };

                if results
                    .send(crate::WorkerMessage::Result(result))
                    .await
                    .is_err()
                {
                    eprintln!(
                        "Worker {} failed to publish result because result channel closed",
                        id
                    );
                    break;
                }

                if stop_signal.load(Ordering::Relaxed) != 0 {
                    println!(
                        "Worker {} observed stop signal after processing a domain",
                        id
                    );
                    break;
                }

                tokio::time::sleep(delay).await;
            }
            None => {
                println!("Worker {} exiting because job queue is closed", id);
                break;
            }
        }
    }
    println!("Worker {} exited", id);
}
