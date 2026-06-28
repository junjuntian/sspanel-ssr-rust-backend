use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicU64, Ordering},
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

/// The set of distinct client IPs a user currently has connections from, with a
/// per-IP refcount so several simultaneous connections from one IP collapse to a
/// single "device". This backs SSPanel's `node_connector` enforcement.
#[derive(Debug, Default)]
pub struct UserIpSet {
    ips: Mutex<HashMap<String, usize>>,
}

/// Tracks the distinct client IPs in flight per user so the relay can enforce
/// SSPanel's `node_connector` as a **device / IP cap** rather than a raw
/// concurrent-connection cap. The original meaning of `node_connector` in the
/// panel is "how many devices/IPs may a user connect from at once" — enforcing
/// it as a concurrent-TCP-connection limit wrongly trips on a single client's
/// parallel connections (a browser, or a 线路测速 that fans out many sockets),
/// which manifested as spurious "线路超时". Counting distinct IPs instead means
/// one device may open as many connections as it likes; only an additional *new*
/// IP beyond the cap is refused. The sets persist across panel polls (a re-sync
/// that does not change a user must not reset their live IPs).
#[derive(Debug, Default)]
pub struct ConnLedger {
    state: Mutex<HashMap<u64, Arc<UserIpSet>>>,
}

impl ConnLedger {
    pub fn ensure_user(&self, user_id: u64) -> Arc<UserIpSet> {
        let mut state = self.state.lock().expect("conn ledger poisoned");
        state.entry(user_id).or_default().clone()
    }

    pub fn remove_stale_users(&self, live_user_ids: &HashSet<u64>) {
        let mut state = self.state.lock().expect("conn ledger poisoned");
        state.retain(|user_id, _| live_user_ids.contains(user_id));
    }
}

/// RAII slot for one live connection from a specific client IP. On acquire it
/// adds the IP to the user's set (or bumps its refcount); on drop it decrements
/// and removes the IP once its last connection closes — so the distinct-IP count
/// cannot leak across normal close, error, or task abort.
pub struct ConnGuard {
    set: Arc<UserIpSet>,
    ip: String,
}

impl ConnGuard {
    /// Reserve a slot for `ip`. An IP already present is **always** admitted (one
    /// device may hold many connections) and only bumps its refcount. A *new* IP
    /// is refused (returns `None`) when `limit > 0` and the user is already at
    /// `limit` distinct IPs. `limit == 0` means unlimited.
    pub fn acquire(set: Arc<UserIpSet>, ip: String, limit: u32) -> Option<Self> {
        {
            let mut ips = set.ips.lock().expect("user ip set poisoned");
            match ips.get_mut(&ip) {
                Some(count) => *count += 1,
                None => {
                    if limit > 0 && ips.len() >= limit as usize {
                        return None;
                    }
                    ips.insert(ip.clone(), 1);
                }
            }
        }
        Some(Self { set, ip })
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let mut ips = self.set.ips.lock().expect("user ip set poisoned");
        if let Some(count) = ips.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                ips.remove(&self.ip);
            }
        }
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
    fn conn_guard_counts_distinct_ips_not_connections() {
        // node_connector enforces a DEVICE/IP cap: with limit=2, two IPs may each
        // open arbitrarily many concurrent connections, but a third *new* IP is
        // refused while the first two are still connected.
        let set = Arc::new(UserIpSet::default());
        let limit = 2;

        // ip A: three concurrent connections — all admitted (one device).
        let a1 = ConnGuard::acquire(set.clone(), "1.1.1.1".into(), limit).unwrap();
        let a2 = ConnGuard::acquire(set.clone(), "1.1.1.1".into(), limit).unwrap();
        let a3 = ConnGuard::acquire(set.clone(), "1.1.1.1".into(), limit).unwrap();
        // ip B: a second device — admitted (distinct count now 2).
        let b1 = ConnGuard::acquire(set.clone(), "2.2.2.2".into(), limit).unwrap();
        assert_eq!(set.ips.lock().unwrap().len(), 2);

        // ip C: a third device — refused (would exceed the 2-IP cap).
        assert!(ConnGuard::acquire(set.clone(), "3.3.3.3".into(), limit).is_none());
        // ...but an extra connection from an already-present IP is still fine.
        let a4 = ConnGuard::acquire(set.clone(), "1.1.1.1".into(), limit).unwrap();

        // Drop all of A's connections: the IP leaves the set, freeing a slot.
        drop((a1, a2, a3, a4));
        assert_eq!(set.ips.lock().unwrap().len(), 1, "ip A fully released");
        // Now a new device fits again.
        let c1 = ConnGuard::acquire(set.clone(), "3.3.3.3".into(), limit).unwrap();
        assert_eq!(set.ips.lock().unwrap().len(), 2);
        drop((b1, c1));
        assert!(set.ips.lock().unwrap().is_empty(), "all released, no leak");
    }

    #[test]
    fn conn_guard_zero_limit_is_unlimited() {
        // limit==0 means unlimited: any number of distinct IPs is admitted but
        // still tracked (so alive/device accounting stays correct).
        let set = Arc::new(UserIpSet::default());
        let g1 = ConnGuard::acquire(set.clone(), "1.1.1.1".into(), 0).unwrap();
        let g2 = ConnGuard::acquire(set.clone(), "2.2.2.2".into(), 0).unwrap();
        let g3 = ConnGuard::acquire(set.clone(), "3.3.3.3".into(), 0).unwrap();
        assert_eq!(set.ips.lock().unwrap().len(), 3);
        drop((g1, g2, g3));
        assert!(set.ips.lock().unwrap().is_empty());
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
