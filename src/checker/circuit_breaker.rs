use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A simple thread-safe circuit breaker
#[derive(Debug)]
pub struct CircuitBreaker {
    pub fail_threshold: u32,       // Number of consecutive failures to trip
    pub recovery_timeout_sec: u64, // Cooldown period in seconds

    // Internal state
    failures: AtomicU32,
    last_failure_time: AtomicU64,
    half_open_probe_until: AtomicU64,
}

pub struct CircuitRequestGuard<'a> {
    breaker: &'a CircuitBreaker,
    probe_lease: u64,
}

impl Drop for CircuitRequestGuard<'_> {
    fn drop(&mut self) {
        if self.probe_lease != 0 {
            let _ = self.breaker.half_open_probe_until.compare_exchange(
                self.probe_lease,
                0,
                Ordering::AcqRel,
                Ordering::Relaxed,
            );
        }
    }
}

impl CircuitBreaker {
    pub fn new(fail_threshold: u32, recovery_timeout_sec: u64) -> Self {
        Self {
            fail_threshold,
            recovery_timeout_sec,
            failures: AtomicU32::new(0),
            last_failure_time: AtomicU64::new(0),
            half_open_probe_until: AtomicU64::new(0),
        }
    }

    /// Check if a request should be allowed (Closed or Half-Open)
    pub fn allow_request(&self) -> bool {
        self.try_claim_request().is_some()
    }

    pub fn acquire_request(&self) -> Option<CircuitRequestGuard<'_>> {
        self.try_claim_request()
            .map(|probe_lease| CircuitRequestGuard {
                breaker: self,
                probe_lease,
            })
    }

    fn try_claim_request(&self) -> Option<u64> {
        let failures = self.failures.load(Ordering::Relaxed);

        // If failures below threshold, circuit is Closed (Healthy)
        if failures < self.fail_threshold {
            return Some(0);
        }

        // Circuit is Open (Tripped), check timeout for Half-Open
        let last_time = self.last_failure_time.load(Ordering::Relaxed);
        let now = Self::current_time();

        if now <= last_time.saturating_add(self.recovery_timeout_sec) {
            return None;
        }

        // Claim the half-open probe. Callers hold a `CircuitRequestGuard`
        // across the request so cancellation releases this claim as well.
        let current_lease = self.half_open_probe_until.load(Ordering::Acquire);
        if current_lease > now {
            return None;
        }
        self.half_open_probe_until
            .compare_exchange(current_lease, u64::MAX, Ordering::AcqRel, Ordering::Relaxed)
            .ok()
            .map(|_| u64::MAX)
    }

    /// Record a successful request
    /// Resets failure count to 0 (closes circuit)
    pub fn record_success(&self) {
        // Optimization: only write if needed to minimize cache invalidation
        if self.failures.load(Ordering::Relaxed) > 0 {
            self.failures.store(0, Ordering::Relaxed);
        }
        self.half_open_probe_until.store(0, Ordering::Release);
    }

    /// Record a failed request
    /// Increments failure count, potentially tripping the circuit
    pub fn record_failure(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
        self.last_failure_time
            .store(Self::current_time(), Ordering::Relaxed);
        self.half_open_probe_until.store(0, Ordering::Release);
    }

    fn current_time() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn half_open_allows_only_one_probe() {
        let breaker = CircuitBreaker::new(1, 0);
        breaker.failures.store(1, Ordering::Relaxed);
        breaker.last_failure_time.store(
            CircuitBreaker::current_time().saturating_sub(1),
            Ordering::Relaxed,
        );

        assert!(breaker.allow_request());
        assert!(!breaker.allow_request());
        breaker.record_success();
        assert!(breaker.allow_request());
    }

    #[test]
    fn expired_half_open_probe_lease_can_be_retried() {
        let breaker = CircuitBreaker::new(1, 0);
        breaker.failures.store(1, Ordering::Relaxed);
        breaker.last_failure_time.store(
            CircuitBreaker::current_time().saturating_sub(1),
            Ordering::Relaxed,
        );
        breaker.half_open_probe_until.store(
            CircuitBreaker::current_time().saturating_sub(1),
            Ordering::Relaxed,
        );

        assert!(breaker.allow_request());
    }

    #[test]
    fn dropped_half_open_request_releases_its_probe() {
        let breaker = CircuitBreaker::new(1, 0);
        breaker.failures.store(1, Ordering::Relaxed);
        breaker.last_failure_time.store(
            CircuitBreaker::current_time().saturating_sub(1),
            Ordering::Relaxed,
        );

        let request = breaker.acquire_request().expect("probe should be allowed");
        drop(request);
        assert!(breaker.acquire_request().is_some());
    }
}
