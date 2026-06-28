//! Hot-swappable per-user lookup tables shared with every listener.
//!
//! The supervisor rebuilds these tables on every panel poll and publishes the
//! new snapshot over a [`watch`] channel. Listeners hold a [`UserTablesWatch`]
//! and read the *current* snapshot at the moment they need it — per-accept for
//! TCP, per-datagram for UDP — so user add/remove/password/enable/disable/policy
//! changes take effect live, **without** tearing down and rebinding the listener
//! socket.
//!
//! This is the root-cause fix for the slight disconnects: previously any user
//! change flipped the listener fingerprint (`auth_users_hash`/`policies_hash`)
//! and forced a full listener restart on the single-port carrier, dropping the
//! accept loop for *all* users on that port and racing the UDP rebind into
//! `EADDRINUSE`. With the tables hot-swapped, the listener never restarts for a
//! user change, so there is nothing to disconnect and no rebind to race.
//!
//! Snapshots are cheap to clone: every field is an `Arc`, so a
//! `tables_rx.borrow().clone()` is just a handful of atomic refcount bumps and
//! never holds the watch borrow across an `.await`.

use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use tokio::sync::watch;

use crate::policy::UserPolicy;
use crate::traffic::{RateLimiter, UserCounters};

/// A consistent, point-in-time view of all per-user lookup tables. Built once
/// per poll by the supervisor and shared (behind an `Arc`) with every listener.
///
/// Each field is itself an `Arc<HashMap>` so a listener can cheaply hand a single
/// table to a helper that wants it by `Arc` (e.g. `ServerSession::new` takes the
/// `auth_users` table by `Arc`) without re-wrapping or cloning the map contents.
#[derive(Default)]
pub struct UserTables {
    /// user_id -> md5(password); the SSR auth table for single-port multi-user
    /// identification. Only populated for `is_multi_user == 0` rows.
    pub auth_users: Arc<HashMap<u64, Vec<u8>>>,
    /// user_id -> traffic counter (u/d byte accumulators reported to the panel).
    pub counters_by_user: Arc<HashMap<u64, Arc<UserCounters>>>,
    /// user_id -> live concurrent-connection counter (for conn_limit enforcement).
    pub conns_by_user: Arc<HashMap<u64, Arc<AtomicUsize>>>,
    /// user_id -> shared per-user token bucket (node_speedlimit).
    pub speeds_by_user: Arc<HashMap<u64, Arc<RateLimiter>>>,
    /// user_id -> connection-time policy (conn_limit / forbidden ip/port). Only
    /// present for users that actually have an active connection policy.
    pub policies: Arc<HashMap<u64, Arc<UserPolicy>>>,
}

/// Sender side held by the supervisor; `send_replace` publishes a new snapshot.
pub type UserTablesTx = watch::Sender<Arc<UserTables>>;
/// Receiver side cloned into each listener; `borrow().clone()` reads the current
/// snapshot.
pub type UserTablesWatch = watch::Receiver<Arc<UserTables>>;

#[cfg(test)]
mod tests {
    use super::*;

    fn tables_with_user(user_id: u64, key: &[u8]) -> Arc<UserTables> {
        let mut auth = HashMap::new();
        auth.insert(user_id, key.to_vec());
        Arc::new(UserTables {
            auth_users: Arc::new(auth),
            ..UserTables::default()
        })
    }

    /// The core hot-swap guarantee: a subscriber created *before* a republish
    /// (i.e. a long-running listener) observes the new snapshot on its next
    /// `borrow()` — no re-subscribe, no listener restart needed.
    #[test]
    fn existing_subscriber_sees_republished_snapshot() {
        let (tx, _) = watch::channel(Arc::new(UserTables::default()));
        let rx = tx.subscribe();
        assert!(rx.borrow().auth_users.is_empty());

        tx.send_replace(tables_with_user(7, b"\x01\x02"));
        // Same receiver, no resubscribe: the listener picks up the new user.
        assert_eq!(rx.borrow().auth_users.get(&7).map(|k| k.as_slice()), Some(&b"\x01\x02"[..]));

        // A password change is just another republish; the snapshot swaps wholesale.
        tx.send_replace(tables_with_user(7, b"\xaa\xbb"));
        assert_eq!(rx.borrow().auth_users.get(&7).map(|k| k.as_slice()), Some(&b"\xaa\xbb"[..]));
    }

    /// A snapshot taken by `borrow().clone()` is stable even after a later
    /// republish, mirroring how an in-flight connection keeps its accept-time
    /// tables while new connections get the fresh snapshot.
    #[test]
    fn cloned_snapshot_is_stable_across_republish() {
        let (tx, rx) = watch::channel(tables_with_user(1, b"old"));
        let snapshot = rx.borrow().clone();
        tx.send_replace(tables_with_user(1, b"new"));
        // The held snapshot is unchanged...
        assert_eq!(snapshot.auth_users.get(&1).map(|k| k.as_slice()), Some(&b"old"[..]));
        // ...while a fresh borrow reflects the republish.
        assert_eq!(rx.borrow().auth_users.get(&1).map(|k| k.as_slice()), Some(&b"new"[..]));
    }
}
