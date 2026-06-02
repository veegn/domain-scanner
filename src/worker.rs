use crate::DomainResult;
use crate::checker::{CheckResult, CheckerRegistry};
use async_channel::Receiver;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Semaphore;
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Number of consecutive successful checks (against a rate-limited service)
/// required before the throttle restores one step of capacity/speed.
const RECOVERY_SUCCESS_THRESHOLD: u64 = 50;

#[derive(Debug)]
pub struct WorkerThrottle {
    delay_ms: AtomicU64,
    pause_until_epoch_ms: AtomicU64,
    max_active_workers: AtomicUsize,
    /// The original (fastest) delay; recovery never speeds up past this.
    base_delay_ms: u64,
    /// The original (highest) worker count; recovery never restores past this.
    worker_cap: usize,
    /// Consecutive successes observed since the last degradation, used to
    /// drive gradual recovery once the rate limit clears.
    recovery_successes: AtomicU64,
}

impl WorkerThrottle {
    pub fn new(initial_delay: Duration, initial_workers: usize) -> Self {
        let delay = (initial_delay.as_millis() as u64).max(1);
        let workers = initial_workers.max(1);
        Self {
            delay_ms: AtomicU64::new(delay),
            pause_until_epoch_ms: AtomicU64::new(0),
            max_active_workers: AtomicUsize::new(workers),
            base_delay_ms: delay,
            worker_cap: workers,
            recovery_successes: AtomicU64::new(0),
        }
    }

    pub fn current_delay(&self) -> Duration {
        Duration::from_millis(self.delay_ms.load(Ordering::Relaxed).max(1))
    }

    pub fn slow_down_by_percent(&self, percent: u64) -> Duration {
        self.recovery_successes.store(0, Ordering::Relaxed);
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
        self.recovery_successes.store(0, Ordering::Relaxed);
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

    pub fn reduce_workers(&self) -> Option<usize> {
        self.recovery_successes.store(0, Ordering::Relaxed);
        let mut current = self.max_active_workers.load(Ordering::Relaxed).max(1);
        loop {
            if current <= 1 {
                return None;
            }

            let next = current - 1;
            match self.max_active_workers.compare_exchange(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(next),
                Err(actual) => current = actual.max(1),
            }
        }
    }

    pub fn current_workers(&self) -> usize {
        self.max_active_workers.load(Ordering::Relaxed).max(1)
    }

    /// Whether the throttle is currently in a degraded state (slowed down or
    /// running with reduced concurrency).
    fn is_degraded(&self) -> bool {
        self.delay_ms.load(Ordering::Relaxed) > self.base_delay_ms
            || self.max_active_workers.load(Ordering::Relaxed) < self.worker_cap
    }

    /// Record a successful check against a rate-limited service. After enough
    /// consecutive successes, restore one step of speed (then concurrency),
    /// reversing the degradation applied on rate limit. Returns `true` when a
    /// recovery step was actually taken.
    pub fn record_progress(&self) -> bool {
        if !self.is_degraded() {
            return false;
        }
        let count = self.recovery_successes.fetch_add(1, Ordering::Relaxed) + 1;
        if count < RECOVERY_SUCCESS_THRESHOLD {
            return false;
        }
        self.recovery_successes.store(0, Ordering::Relaxed);
        self.recover_step()
    }

    /// Restore one increment of capacity: first bring the delay back toward the
    /// base, and only once at the base start adding workers back (the reverse
    /// of the degradation order). Returns `true` if anything changed.
    fn recover_step(&self) -> bool {
        let base = self.base_delay_ms;
        let mut current = self.delay_ms.load(Ordering::Relaxed);
        while current > base {
            let reduced = (current.saturating_mul(100) / 120).max(base);
            match self.delay_ms.compare_exchange(
                current,
                reduced,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }

        let mut workers = self.max_active_workers.load(Ordering::Relaxed);
        loop {
            if workers >= self.worker_cap {
                return false;
            }
            match self.max_active_workers.compare_exchange(
                workers,
                workers + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => workers = actual,
            }
        }
    }

    pub async fn wait_until_ready(
        &self,
        worker_id: usize,
        stop_signal: &AtomicU8,
        jobs: &Receiver<String>,
    ) -> bool {
        loop {
            if stop_signal.load(Ordering::Relaxed) != 0 {
                return false;
            }

            // If the job channel has been closed (no more work will ever
            // arrive), stop parking and let the worker fall through to recv()
            // so it can drain any remainder and then exit. Without this, a
            // worker parked because of a reduced concurrency limit would never
            // release its result-channel sender, and the scan runtime's main
            // loop would never observe the channel closing.
            if jobs.is_closed() {
                return true;
            }

            let max_workers = self.max_active_workers.load(Ordering::Relaxed).max(1);
            if worker_id > max_workers {
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            }

            let pause_until = self.pause_until_epoch_ms.load(Ordering::Relaxed);
            let now = now_epoch_millis();
            if pause_until <= now {
                return true;
            }

            let sleep_ms = pause_until.saturating_sub(now).min(250);
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
    jobs: Receiver<String>,
    results: mpsc::Sender<crate::WorkerMessage>,
    throttle: Arc<WorkerThrottle>,
    registry: Arc<CheckerRegistry>,
    stop_signal: Arc<AtomicU8>,
    global_check_permits: Arc<Semaphore>,
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

        if !throttle.wait_until_ready(id, &stop_signal, &jobs).await {
            debug!(
                target: "domain_scanner::worker",
                context = "lifecycle",
                worker_id = id,
                "worker exiting while waiting on throttle"
            );
            break;
        }

        let domain_name = jobs.recv().await.ok();

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

                let permit = match global_check_permits.clone().acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => {
                        warn!(
                            target: "domain_scanner::worker",
                            context = "throttle",
                            worker_id = id,
                            "global checker semaphore closed"
                        );
                        break;
                    }
                };

                // Use the registry to check the domain
                let check_result: CheckResult = registry.check(&domain).await;
                drop(permit);

                // Determine if WHOIS/RDAP was reached (for adaptive delay)
                let reached_rate_limited_service = check_result.trace.iter().any(|s| {
                    s.starts_with("WHOIS: ") || s.starts_with("RDAP: ") || s.starts_with("DoH: ")
                });

                // A clean result from a throttled service signals the rate limit
                // may have cleared; let the throttle gradually restore speed and
                // concurrency that an earlier rate limit had taken away.
                if reached_rate_limited_service
                    && !check_result.rate_limited
                    && !check_result.retryable
                {
                    throttle.record_progress();
                }

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

                if reached_rate_limited_service {
                    tokio::time::sleep(throttle.current_delay()).await;
                }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: a worker parked because of a reduced concurrency limit must
    /// be released once the job channel closes, otherwise it would hold its
    /// result-channel sender forever and the scan would never finish.
    #[tokio::test]
    async fn wait_until_ready_releases_parked_worker_when_jobs_closed() {
        let throttle = WorkerThrottle::new(Duration::from_millis(1), 4);
        // Simulate a rate-limit-induced reduction: max workers drops to 3, so
        // worker #4 would normally park indefinitely.
        throttle.reduce_workers();
        assert_eq!(throttle.current_workers(), 3);

        let (tx, rx) = async_channel::bounded::<String>(1);
        drop(tx); // close the channel (mirrors jobs_tx.take() at end of scan)

        let stop = AtomicU8::new(0); // TaskSignal::Run -> never stops via signal
        let ready = tokio::time::timeout(
            Duration::from_secs(2),
            throttle.wait_until_ready(4, &stop, &rx),
        )
        .await
        .expect("wait_until_ready must not hang when the job channel is closed");

        assert!(
            ready,
            "parked worker should be released so it can drain and exit"
        );
    }

    /// The throttle must recover speed and then concurrency after sustained
    /// successes, reversing the degradation applied on rate limit.
    #[test]
    fn record_progress_restores_capacity_after_sustained_successes() {
        let throttle = WorkerThrottle::new(Duration::from_millis(10), 3);

        // Degrade: one fewer worker and a slower delay.
        assert_eq!(throttle.reduce_workers(), Some(2));
        throttle.slow_down_by_percent(20);
        assert!(throttle.current_delay() > Duration::from_millis(10));
        assert_eq!(throttle.current_workers(), 2);

        // Below the threshold, nothing changes.
        for _ in 0..(RECOVERY_SUCCESS_THRESHOLD - 1) {
            assert!(!throttle.record_progress());
        }
        // Crossing the threshold restores speed toward the base first.
        assert!(throttle.record_progress());
        assert_eq!(throttle.current_delay(), Duration::from_millis(10));
        assert_eq!(throttle.current_workers(), 2);

        // The next threshold restores a worker once delay is back at base.
        for _ in 0..RECOVERY_SUCCESS_THRESHOLD {
            throttle.record_progress();
        }
        assert_eq!(throttle.current_workers(), 3);

        // Fully recovered: further progress is a no-op.
        assert!(!throttle.record_progress());
    }

    /// A fresh, healthy throttle should not "recover" past its starting point.
    #[test]
    fn record_progress_is_noop_when_not_degraded() {
        let throttle = WorkerThrottle::new(Duration::from_millis(5), 4);
        for _ in 0..(RECOVERY_SUCCESS_THRESHOLD * 2) {
            assert!(!throttle.record_progress());
        }
        assert_eq!(throttle.current_workers(), 4);
        assert_eq!(throttle.current_delay(), Duration::from_millis(5));
    }
}
