use std::{
    collections::HashMap,
    hash::Hash,
    time::{Duration, Instant},
};

#[derive(Debug)]
struct Entry<V> {
    value: V,
    last_seen: Instant,
}

/// A map whose memory is strictly bounded by `capacity` and whose entries expire
/// after `ttl` of inactivity.
///
/// Design note: an earlier version kept an auxiliary `VecDeque` "order" log and
/// pushed to it on every `touch`, draining only from the front. Under a hot key
/// being touched repeatedly (e.g. a UDP peer sending thousands of packets/sec)
/// that log could grow to millions of entries within a TTL window even though
/// the map itself stayed tiny — exactly the unbounded-growth failure mode this
/// project must avoid. This version keeps no per-touch log at all: the map is
/// the only state, so live memory never exceeds `capacity` entries.
#[derive(Debug)]
pub struct BoundedTtlMap<K, V> {
    ttl: Duration,
    capacity: usize,
    map: HashMap<K, Entry<V>>,
}

impl<K, V> BoundedTtlMap<K, V>
where
    K: Eq + Hash + Clone,
{
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            ttl,
            capacity: capacity.max(1),
            map: HashMap::new(),
        }
    }

    /// Insert `key` (creating its value lazily) or refresh an existing entry's
    /// last-seen timestamp. O(1) amortized; only touches the single key.
    ///
    /// Currently the relay path constructs values asynchronously and uses
    /// [`touch`](Self::touch) + [`insert`](Self::insert) instead; this is kept as
    /// the synchronous convenience entry point for session/alive-IP bookkeeping.
    #[allow(dead_code)]
    pub fn touch_or_insert_with(&mut self, key: K, make_value: impl FnOnce() -> V) {
        let now = Instant::now();
        if let Some(entry) = self.map.get_mut(&key) {
            entry.last_seen = now;
            return;
        }
        // New key. Drop expired entries first, then enforce capacity by evicting
        // the least-recently-seen entry. Both operations are bounded by
        // `capacity`, so they never become a runaway cost.
        self.evict_expired(now);
        if self.map.len() >= self.capacity {
            self.evict_oldest();
        }
        self.map.insert(key, Entry { value: make_value(), last_seen: now });
    }

    /// Refresh an existing entry's last-seen timestamp and return a reference to
    /// its value. Returns `None` if the key is absent. Useful when the value must
    /// be constructed asynchronously (so `touch_or_insert_with` can't be used):
    /// call `touch`, and on `None` build the value and [`insert`](Self::insert).
    pub fn touch(&mut self, key: &K) -> Option<&V> {
        if let Some(entry) = self.map.get_mut(key) {
            entry.last_seen = Instant::now();
            Some(&entry.value)
        } else {
            None
        }
    }

    /// Insert a pre-built value, enforcing TTL and capacity exactly like
    /// `touch_or_insert_with`. Replaces any existing entry for `key` (dropping the
    /// old value, which lets RAII guards on the value run their cleanup).
    pub fn insert(&mut self, key: K, value: V) {
        let now = Instant::now();
        self.evict_expired(now);
        if !self.map.contains_key(&key) && self.map.len() >= self.capacity {
            self.evict_oldest();
        }
        self.map.insert(key, Entry { value, last_seen: now });
    }

    /// Drop all entries whose TTL has elapsed.
    pub fn expire(&mut self) {
        self.evict_expired(Instant::now());
    }

    pub fn retain(&mut self, mut keep: impl FnMut(&K, &V) -> bool) {
        self.map.retain(|key, entry| keep(key, &entry.value));
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.map.values().map(|entry| &entry.value)
    }

    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.map.keys()
    }

    fn evict_expired(&mut self, now: Instant) {
        let ttl = self.ttl;
        self.map
            .retain(|_, entry| now.duration_since(entry.last_seen) < ttl);
    }

    fn evict_oldest(&mut self) {
        if let Some(oldest_key) = self
            .map
            .iter()
            .min_by_key(|(_, entry)| entry.last_seen)
            .map(|(key, _)| key.clone())
        {
            self.map.remove(&oldest_key);
        }
    }
}
