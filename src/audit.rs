//! Relay-side auditing: feeds session / alive-IP / detect-log events from the
//! per-user listener tasks back to the supervisor, and distributes the panel's
//! compiled detect rules out to those tasks.
//!
//! The relay tasks never touch the supervisor's bounded maps directly. Instead
//! they emit [`RelayEvent`]s over a bounded mpsc channel (the supervisor owns the
//! receiver and records into its maps), and read the current rule set from a
//! `watch` channel the supervisor updates on each poll. Sends are best-effort
//! (`try_send`): if the channel is momentarily full we drop the event rather than
//! block the hot relay path, keeping memory and latency bounded.

use std::{collections::HashSet, sync::Arc};

use regex::bytes::Regex;
use tokio::sync::{mpsc, watch};
use tracing::warn;

use crate::panel::DetectRule;

/// An audit observation produced by a relay task.
#[derive(Debug)]
pub enum RelayEvent {
    /// A client completed an SSR handshake (TCP) or opened a new association
    /// (UDP). Populates both the session map (keyed by ip:port) and the
    /// alive-IP map (keyed by ip).
    Connect {
        user_id: u64,
        ip: String,
        peer: String,
    },
    /// A decrypted upload payload matched detect rule `list_id`.
    Detect {
        user_id: u64,
        list_id: u64,
        ip: String,
    },
}

pub type EventSender = mpsc::Sender<RelayEvent>;
pub type EventReceiver = mpsc::Receiver<RelayEvent>;

/// Bounded so a burst of events can never grow memory without limit; on overflow
/// `try_send` drops the event (the supervisor's maps also expire on TTL anyway).
pub const EVENT_CHANNEL_CAPACITY: usize = 1024;

pub fn event_channel() -> (EventSender, EventReceiver) {
    mpsc::channel(EVENT_CHANNEL_CAPACITY)
}

/// A detect rule with its regex pre-compiled. Matching is done on raw bytes,
/// since upload payloads are not necessarily UTF-8.
pub struct CompiledRule {
    pub id: u64,
    re: Regex,
}

impl CompiledRule {
    pub fn is_match(&self, data: &[u8]) -> bool {
        self.re.is_match(data)
    }
}

/// Shared, immutable snapshot of the active rule set. Cheap to clone (Arc).
pub type RuleSet = Arc<Vec<CompiledRule>>;
pub type RuleWatch = watch::Receiver<RuleSet>;

pub fn empty_rules() -> RuleSet {
    Arc::new(Vec::new())
}

/// Compile panel detect rules, skipping any with an empty or invalid regex.
pub fn compile_rules(rules: &[DetectRule]) -> RuleSet {
    let mut compiled = Vec::new();
    for rule in rules {
        if rule.regex.trim().is_empty() {
            continue;
        }
        match Regex::new(&rule.regex) {
            Ok(re) => compiled.push(CompiledRule { id: rule.id, re }),
            Err(err) => warn!(
                id = rule.id,
                name = %rule.name,
                regex = %rule.regex,
                error = %err,
                "skipping uncompilable detect rule"
            ),
        }
    }
    Arc::new(compiled)
}

/// Best-effort emit a connect (session + alive-IP) event.
pub fn report_connect(events: &EventSender, user_id: u64, ip: &str, peer: &str) {
    let _ = events.try_send(RelayEvent::Connect {
        user_id,
        ip: ip.to_string(),
        peer: peer.to_string(),
    });
}

/// Scan one decrypted upload chunk against `rules`, emitting a Detect event for
/// every matching rule. Used by the UDP path, where there is no cheap per-peer
/// mutable state to dedup against (the supervisor's detect-log map dedups by
/// user+rule+ip, and `try_send` drops under pressure).
///
/// Returns `true` if any rule matched, so the caller can drop the datagram when
/// node-side audit blocking is enabled.
pub fn scan_payload(
    rules: &RuleSet,
    events: &EventSender,
    user_id: u64,
    ip: &str,
    data: &[u8],
) -> bool {
    if data.is_empty() || rules.is_empty() {
        return false;
    }
    let mut matched = false;
    for rule in rules.iter() {
        if rule.is_match(data) {
            matched = true;
            let _ = events.try_send(RelayEvent::Detect {
                user_id,
                list_id: rule.id,
                ip: ip.to_string(),
            });
        }
    }
    matched
}

/// Per-connection auditor for the TCP path. Holds a dedup set so a rule that
/// keeps matching across many chunks of one connection is reported only once,
/// which also shields the supervisor from repeated map inserts on a hot stream.
pub struct ConnectionAuditor {
    user_id: u64,
    ip: String,
    peer: String,
    events: EventSender,
    rules: RuleWatch,
    matched: HashSet<u64>,
}

impl ConnectionAuditor {
    pub fn new(
        user_id: u64,
        ip: String,
        peer: String,
        events: EventSender,
        rules: RuleWatch,
    ) -> Self {
        Self {
            user_id,
            ip,
            peer,
            events,
            rules,
            matched: HashSet::new(),
        }
    }

    /// Emit the connect event once the SSR handshake has succeeded.
    pub fn report_connect(&self) {
        report_connect(&self.events, self.user_id, &self.ip, &self.peer);
    }

    /// Scan a decrypted upload chunk; emit Detect for newly-matched rules.
    ///
    /// Returns `true` if this chunk matched any rule (whether or not it was
    /// already reported on this connection), so the caller can drop the
    /// connection when node-side audit blocking is enabled.
    ///
    /// Note: matching is per-chunk, so a pattern split across a read boundary is
    /// not detected — this mirrors the per-buffer scanning of the original SSR
    /// audit and keeps the cost bounded by the rule count.
    pub fn scan(&mut self, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        // Clone the Arc out so the watch borrow is released before we mutate
        // `self.matched`.
        let rules = self.rules.borrow().clone();
        if rules.is_empty() {
            return false;
        }
        let mut matched_now = false;
        for rule in rules.iter() {
            if !rule.is_match(data) {
                continue;
            }
            matched_now = true;
            if self.matched.insert(rule.id) {
                let _ = self.events.try_send(RelayEvent::Detect {
                    user_id: self.user_id,
                    list_id: rule.id,
                    ip: self.ip.clone(),
                });
            }
        }
        matched_now
    }
}
