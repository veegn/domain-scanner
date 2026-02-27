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
}

impl CircuitBreaker {
    pub fn new(fail_threshold: u32, recovery_timeout_sec: u64) -> Self {
        Self {
            fail_threshold,
            recovery_timeout_sec,
            failures: AtomicU32::new(0),
            last_failure_time: AtomicU64::new(0),
        }
    }

    /// Check if a request should be allowed (Closed or Half-Open)
    pub fn allow_request(&self) -> bool {
        let failures = self.failures.load(Ordering::Relaxed);

        // If failures below threshold, circuit is Closed (Healthy)
        if failures < self.fail_threshold {
            return true;
        }

        // Circuit is Open (Tripped), check timeout for Half-Open
        let last_time = self.last_failure_time.load(Ordering::Relaxed);
        let now = Self::current_time();

        // If recovery time passed, allow request (Trial)
        now > last_time + self.recovery_timeout_sec
    }

    /// Record a successful request
    /// Resets failure count to 0 (closes circuit)
    pub fn record_success(&self) {
        // Optimization: only write if needed to minimize cache invalidation
        if self.failures.load(Ordering::Relaxed) > 0 {
            self.failures.store(0, Ordering::Relaxed);
        }
    }

    /// Record a failed request
    /// Increments failure count, potentially tripping the circuit
    pub fn record_failure(&self) {
        let _current = self.failures.fetch_add(1, Ordering::Relaxed);
        // Update timestamp on every failure so the window extends
        self.last_failure_time
            .store(Self::current_time(), Ordering::Relaxed);

        // Optional: Log when circuit trips
        // if current + 1 == self.fail_threshold {
        //    println!("Circuit breaker tripped!");
        // }
    }

    fn current_time() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}
