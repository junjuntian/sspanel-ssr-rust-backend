use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use tokio::time::sleep;

#[derive(Debug, Default)]
pub struct UserCounters {
    upload: AtomicU64,
    download: AtomicU64,
}

impl UserCounters {
    pub fn record_upload(&self, bytes: u64) {
        self.upload.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_download(&self, bytes: u64) {
        self.download.fetch_add(bytes, Ordering::Relaxed);
    }

    fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            upload: self.upload.load(Ordering::Relaxed),
            download: self.download.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct CounterSnapshot {
    upload: u64,
    download: u64,
}

#[derive(Debug, Clone)]
pub struct TrafficDelta {
    pub user_id: u64,
    pub upload: u64,
    pub download: u64,
    checkpoint: CounterSnapshot,
}

#[derive(Debug, Default)]
struct TrafficState {
    counters: HashMap<u64, Arc<UserCounters>>,
    checkpoints: HashMap<u64, CounterSnapshot>,
}

#[derive(Debug, Default)]
pub struct TrafficLedger {
    state: Mutex<TrafficState>,
}

impl TrafficLedger {
    pub fn ensure_user(&self, user_id: u64) -> Arc<UserCounters> {
        let mut state = self.state.lock().expect("traffic ledger poisoned");
        if let Some(counters) = state.counters.get(&user_id) {
            return counters.clone();
        }
        state.checkpoints.entry(user_id).or_default();
        let counters = Arc::new(UserCounters::default());
        state.counters.insert(user_id, counters.clone());
        counters
    }

    pub fn remove_stale_users(&self, live_user_ids: &HashSet<u64>) {
        let mut state = self.state.lock().expect("traffic ledger poisoned");
        state.counters.retain(|user_id, _| live_user_ids.contains(user_id));
        state.checkpoints.retain(|user_id, _| live_user_ids.contains(user_id));
    }

    pub fn pending_deltas(&self) -> Vec<TrafficDelta> {
        let state = self.state.lock().expect("traffic ledger poisoned");
        let mut deltas = Vec::new();
        for (user_id, counters) in &state.counters {
            let current = counters.snapshot();
            let checkpoint = state.checkpoints.get(user_id).copied().unwrap_or_default();
            let upload = current.upload.saturating_sub(checkpoint.upload);
            let download = current.download.saturating_sub(checkpoint.download);
            if upload > 0 || download > 0 {
                deltas.push(TrafficDelta {
                    user_id: *user_id,
                    upload,
                    download,
                    checkpoint: current,
                });
            }
        }
        deltas
    }

    pub fn mark_reported(&self, deltas: &[TrafficDelta]) {
        let mut state = self.state.lock().expect("traffic ledger poisoned");
        for delta in deltas {
            if state.counters.contains_key(&delta.user_id) {
                state.checkpoints.insert(delta.user_id, delta.checkpoint);
            }
        }
    }
}

/// Tracks the number of in-flight connections per user so the relay can enforce
/// SSPanel's `node_connector` limit. The counters persist across panel polls (a
/// re-sync that does not change a user must not reset their live count).
#[derive(Debug, Default)]
pub struct ConnLedger {
    state: Mutex<HashMap<u64, Arc<AtomicUsize>>>,
}

impl ConnLedger {
    pub fn ensure_user(&self, user_id: u64) -> Arc<AtomicUsize> {
        let mut state = self.state.lock().expect("conn ledger poisoned");
        state.entry(user_id).or_default().clone()
    }

    pub fn remove_stale_users(&self, live_user_ids: &HashSet<u64>) {
        let mut state = self.state.lock().expect("conn ledger poisoned");
        state.retain(|user_id, _| live_user_ids.contains(user_id));
    }
}

/// RAII slot for one live connection. Increments the user's counter on
/// [`ConnGuard::acquire`] and decrements it on drop (normal close, error, or
/// task abort), so the count cannot leak.
pub struct ConnGuard {
    counter: Arc<AtomicUsize>,
}

impl ConnGuard {
    /// Reserve a connection slot. Returns `None` when `limit > 0` and the user is
    /// already at the limit (the reservation is rolled back before returning).
    pub fn acquire(counter: Arc<AtomicUsize>, limit: u32) -> Option<Self> {
        let prev = counter.fetch_add(1, Ordering::AcqRel);
        if limit > 0 && prev >= limit as usize {
            counter.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(Self { counter })
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Per-user token-bucket rate limiter (bytes/sec), shared across all of a user's
/// connections so SSPanel's `node_speedlimit` caps the user's *aggregate*
/// throughput rather than per-connection. A rate of 0 means unlimited and makes
/// [`RateLimiter::acquire`] a no-op. The rate can be updated live when the panel
/// value changes (so "面板设多少就限多少" without a listener restart).
pub struct RateLimiter {
    inner: Mutex<Bucket>,
}

struct Bucket {
    /// bytes/sec; 0 = unlimited.
    rate: f64,
    /// max tokens (burst ceiling).
    capacity: f64,
    tokens: f64,
    last: Instant,
}

fn refill(b: &mut Bucket) {
    let now = Instant::now();
    if b.rate <= 0.0 {
        b.last = now;
        return;
    }
    let elapsed = now.duration_since(b.last).as_secs_f64();
    b.last = now;
    b.tokens = (b.tokens + elapsed * b.rate).min(b.capacity);
}

impl RateLimiter {
    /// ~1s of burst, but at least 256 KiB so a single relay chunk (<= 64 KiB)
    /// always fits in the bucket and `acquire` can make progress.
    fn capacity_for(rate: f64) -> f64 {
        const MIN_BURST: f64 = 256.0 * 1024.0;
        rate.max(MIN_BURST)
    }

    pub fn new(rate_bps: u64) -> Self {
        let rate = rate_bps as f64;
        let capacity = Self::capacity_for(rate);
        Self {
            inner: Mutex::new(Bucket {
                rate,
                capacity,
                tokens: capacity,
                last: Instant::now(),
            }),
        }
    }

    /// Update the cap live. Cheap no-op when unchanged.
    pub fn set_rate(&self, rate_bps: u64) {
        let rate = rate_bps as f64;
        let mut b = self.inner.lock().expect("rate limiter poisoned");
        if (rate - b.rate).abs() < f64::EPSILON {
            return;
        }
        refill(&mut b);
        b.rate = rate;
        b.capacity = Self::capacity_for(rate);
        if b.tokens > b.capacity {
            b.tokens = b.capacity;
        }
    }

    /// Async-block until `amount` bytes may be sent under the cap. Never holds the
    /// lock across the sleep, so the per-user bucket can be shared by many
    /// connections without serializing their awaits.
    pub async fn acquire(&self, amount: usize) {
        let amount = amount as f64;
        loop {
            let wait = {
                let mut b = self.inner.lock().expect("rate limiter poisoned");
                if b.rate <= 0.0 {
                    return;
                }
                refill(&mut b);
                // Never wait for more than the bucket can ever hold (guards against
                // a single chunk larger than capacity deadlocking the loop).
                let need = amount.min(b.capacity);
                if b.tokens >= need {
                    b.tokens -= need;
                    return;
                }
                Duration::from_secs_f64((need - b.tokens) / b.rate)
            };
            sleep(wait).await;
        }
    }
}

/// Per-user rate limiters, persistent across panel polls so an unchanged user
/// keeps their bucket state. Mirrors [`ConnLedger`]; `ensure_user` doubles as the
/// live rate-update path.
#[derive(Default)]
pub struct SpeedLedger {
    state: Mutex<HashMap<u64, Arc<RateLimiter>>>,
}

impl SpeedLedger {
    /// Get or create the user's limiter, updating its rate to the current panel
    /// value. `rate_bps == 0` means unlimited.
    pub fn ensure_user(&self, user_id: u64, rate_bps: u64) -> Arc<RateLimiter> {
        let mut state = self.state.lock().expect("speed ledger poisoned");
        match state.get(&user_id) {
            Some(rl) => {
                rl.set_rate(rate_bps);
                rl.clone()
            }
            None => {
                let rl = Arc::new(RateLimiter::new(rate_bps));
                state.insert(user_id, rl.clone());
                rl
            }
        }
    }

    pub fn remove_stale_users(&self, live_user_ids: &HashSet<u64>) {
        let mut state = self.state.lock().expect("speed ledger poisoned");
        state.retain(|user_id, _| live_user_ids.contains(user_id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rate_limiter_unlimited_is_noop() {
        let rl = RateLimiter::new(0);
        // A huge acquire on an unlimited bucket must return effectively instantly.
        let start = Instant::now();
        rl.acquire(1_000_000_000).await;
        assert!(start.elapsed() < Duration::from_millis(50));
    }

    #[tokio::test(start_paused = true)]
    async fn rate_limiter_throttles_after_burst() {
        // 1 MiB/s. Capacity == max(rate, 256KiB) == 1 MiB of burst.
        let rl = RateLimiter::new(1024 * 1024);
        // Drain the full burst instantly.
        let start = Instant::now();
        rl.acquire(1024 * 1024).await;
        assert!(start.elapsed() < Duration::from_millis(50));
        // The next 1 MiB must wait ~1s for the bucket to refill at 1 MiB/s.
        rl.acquire(1024 * 1024).await;
        assert!(start.elapsed() >= Duration::from_millis(900));
    }

    #[test]
    fn set_rate_reclamps_tokens() {
        let rl = RateLimiter::new(10 * 1024 * 1024); // 10 MiB/s -> cap 10 MiB
        rl.set_rate(0); // unlimited
        {
            let b = rl.inner.lock().unwrap();
            assert_eq!(b.rate, 0.0);
        }
        rl.set_rate(1024); // 1 KiB/s -> cap floored at 256 KiB
        let b = rl.inner.lock().unwrap();
        assert!(b.tokens <= b.capacity);
    }
}
