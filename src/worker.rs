use crate::DomainResult;
use crate::checker::{CheckResult, CheckerRegistry};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tracing::{debug, warn};

#[derive(Debug, Default)]
pub struct WorkerThrottle {
    delay_ms: AtomicU64,
    pause_until_epoch_ms: AtomicU64,
}

impl WorkerThrottle {
    pub fn new(initial_delay: Duration) -> Self {
        Self {
            delay_ms: AtomicU64::new(initial_delay.as_millis() as u64),
            pause_until_epoch_ms: AtomicU64::new(0),
        }
    }

    pub fn current_delay(&self) -> Duration {
        Duration::from_millis(self.delay_ms.load(Ordering::Relaxed).max(1))
    }

    pub fn slow_down_by_percent(&self, percent: u64) -> Duration {
        let mut current = self.delay_ms.load(Ordering::Relaxed).max(1);
        loop {
            let increased = current.saturating_mul(100 + percent).saturating_add(99) / 100;
            match self.delay_ms.compare_exchange(
                current,
                increased.max(1),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Duration::from_millis(increased.max(1)),
                Err(actual) => current = actual.max(1),
            }
        }
    }

    pub fn pause_for(&self, duration: Duration) -> u64 {
        let target = now_epoch_millis().saturating_add(duration.as_millis() as u64);
        let mut current = self.pause_until_epoch_ms.load(Ordering::Relaxed);
        loop {
            let next = current.max(target);
            match self.pause_until_epoch_ms.compare_exchange(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return next,
                Err(actual) => current = actual,
            }
        }
    }

    pub async fn wait_if_paused(&self) {
        loop {
            let pause_until = self.pause_until_epoch_ms.load(Ordering::Relaxed);
            let now = now_epoch_millis();
            if pause_until <= now {
                return;
            }

            let sleep_ms = pause_until.saturating_sub(now).min(1_000);
            tokio::time::sleep(Duration::from_millis(sleep_ms.max(1))).await;
        }
    }
}

fn now_epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub async fn worker(
    id: usize,
    jobs: Arc<Mutex<mpsc::Receiver<String>>>,
    results: mpsc::Sender<crate::WorkerMessage>,
    throttle: Arc<WorkerThrottle>,
    registry: Arc<CheckerRegistry>,
    stop_signal: Arc<AtomicU8>,
) {
    loop {
        if stop_signal.load(Ordering::Relaxed) != 0 {
            debug!(
                target: "domain_scanner::worker",
                context = "lifecycle",
                worker_id = id,
                "worker stopping due to task signal"
            );
            break;
        }

        throttle.wait_if_paused().await;

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
                    warn!(
                        target: "domain_scanner::worker",
                        context = "publish",
                        worker_id = id,
                        "failed to publish scanning event because result channel closed"
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
                    warn!(
                        target: "domain_scanner::worker",
                        context = "publish",
                        worker_id = id,
                        "failed to publish result because result channel closed"
                    );
                    break;
                }

                if stop_signal.load(Ordering::Relaxed) != 0 {
                    debug!(
                        target: "domain_scanner::worker",
                        context = "lifecycle",
                        worker_id = id,
                        "worker observed stop signal after processing a domain"
                    );
                    break;
                }

                tokio::time::sleep(throttle.current_delay()).await;
            }
            None => {
                debug!(
                    target: "domain_scanner::worker",
                    context = "lifecycle",
                    worker_id = id,
                    "worker exiting because job queue is closed"
                );
                break;
            }
        }
    }
}
