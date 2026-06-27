use std::{
    collections::{HashMap, HashSet, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    sync::Arc,
    time::Instant,
};

use anyhow::{anyhow, Result};
use tracing::{debug, info, warn};

use tokio::sync::watch;

use crate::{
    audit::{self, EventReceiver, EventSender, RelayEvent, RuleSet, RuleWatch},
    config::Config,
    panel::{AliveIpReport, DetectLogReport, PanelClient, PanelUser},
    policy::{EnforcementConfig, UserPolicy},
    runtime::state::BoundedTtlMap,
    ssr::Profile,
    tcp::{self, TcpListenerTask},
    traffic::{ConnLedger, RateLimiter, SpeedLedger, TrafficLedger},
    udp::{self, UdpListenerTask},
};

use std::sync::atomic::AtomicUsize;

#[derive(Debug, Clone, PartialEq, Eq)]
struct UserFingerprint {
    port: u16,
    password: String,
    profile: Profile,
    is_multi_user: i64,
    auth_users_hash: u64,
    policies_hash: u64,
}

struct ActiveUser {
    fingerprint: UserFingerprint,
    tcp: Option<TcpListenerTask>,
    udp: Option<UdpListenerTask>,
}

impl ActiveUser {
    async fn stop(self) {
        if let Some(tcp) = self.tcp {
            tcp.stop().await;
        }
        if let Some(udp) = self.udp {
            udp.stop().await;
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct AliveIpKey {
    user_id: u64,
    ip: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct DetectLogKey {
    user_id: u64,
    list_id: u64,
    ip: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct SessionKey {
    user_id: u64,
    peer: String,
}

fn hash_auth_users(users: &HashMap<u64, Vec<u8>>) -> u64 {
    let mut ordered: Vec<_> = users.iter().collect();
    ordered.sort_by_key(|(user_id, _)| **user_id);
    let mut hasher = DefaultHasher::new();
    for (user_id, key) in ordered {
        user_id.hash(&mut hasher);
        key.hash(&mut hasher);
    }
    hasher.finish()
}

/// Fingerprint hash of the per-user policies that the listener captures *at spawn
/// time* and therefore can only pick up via a listener restart:
/// `conn_limit`, `forbidden_ips`, `forbidden_ports`.
///
/// `speed_limit_bps` is deliberately excluded: the rate cap is applied through a
/// persistent shared token bucket (`SpeedLedger`) whose rate is updated in place
/// on every poll (`ensure_user` -> `set_rate`). Folding it into the fingerprint
/// would needlessly rebuild the listener on every speed change — dropping the
/// accept loop for *all* users on a single-port carrier — for a value that takes
/// effect live without any restart. Keeping it out makes speed changes 无感.
fn hash_policies(policies: &HashMap<u64, Arc<UserPolicy>>) -> u64 {
    let mut ordered: Vec<_> = policies.iter().collect();
    ordered.sort_by_key(|(user_id, _)| **user_id);
    let mut hasher = DefaultHasher::new();
    for (user_id, policy) in ordered {
        user_id.hash(&mut hasher);
        policy.conn_limit.hash(&mut hasher);
        policy.forbidden_ips.hash(&mut hasher);
        policy.forbidden_ports.hash(&mut hasher);
        // speed_limit_bps intentionally omitted (applied live via SpeedLedger).
    }
    hasher.finish()
}

pub struct BackendRuntime {
    config: Config,
    panel: PanelClient,
    traffic: TrafficLedger,
    conns: ConnLedger,
    speeds: SpeedLedger,
    active_users: HashMap<u16, ActiveUser>,
    sessions: BoundedTtlMap<SessionKey, ()>,
    alive_ips: BoundedTtlMap<AliveIpKey, ()>,
    detect_logs: BoundedTtlMap<DetectLogKey, DetectLogReport>,
    started_at: Instant,
    /// Relay tasks emit session / alive-IP / detect events here; the run loop
    /// drains the receiver into the maps above. `events_tx` is cloned into each
    /// spawned listener.
    events_tx: EventSender,
    events_rx: Option<EventReceiver>,
    /// Compiled detect rules, broadcast to every listener. Updated on each poll.
    detect_rules_tx: watch::Sender<RuleSet>,
    detect_rules_rx: RuleWatch,
}

impl BackendRuntime {
    pub fn new(config: Config, panel: PanelClient) -> Self {
        let (events_tx, events_rx) = audit::event_channel();
        let (detect_rules_tx, detect_rules_rx) = watch::channel(audit::empty_rules());
        Self {
            alive_ips: BoundedTtlMap::new(config.limits.alive_ip_ttl(), config.limits.max_alive_ips),
            sessions: BoundedTtlMap::new(config.limits.session_ttl(), config.limits.max_sessions),
            detect_logs: BoundedTtlMap::new(
                config.limits.detect_log_ttl(),
                config.limits.max_detect_logs,
            ),
            config,
            panel,
            traffic: TrafficLedger::default(),
            conns: ConnLedger::default(),
            speeds: SpeedLedger::default(),
            active_users: HashMap::new(),
            started_at: Instant::now(),
            events_tx,
            events_rx: Some(events_rx),
            detect_rules_tx,
            detect_rules_rx,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        self.initial_panel_probe().await;
        self.refresh_detect_rules().await;
        self.sync_users().await?;

        // The relay tasks emit audit events here; drain them in the run loop.
        let mut events_rx = self
            .events_rx
            .take()
            .expect("event receiver already taken");

        let mut poll = tokio::time::interval(self.config.panel.poll_interval());
        let mut traffic = tokio::time::interval(self.config.panel.traffic_report_interval());
        let mut heartbeat = tokio::time::interval(self.config.panel.heartbeat_interval());

        loop {
            tokio::select! {
                _ = shutdown_signal() => {
                    info!("shutdown signal received");
                    break;
                }
                Some(event) = events_rx.recv() => {
                    self.record_event(event);
                }
                _ = poll.tick() => {
                    if let Err(err) = self.sync_users().await {
                        warn!(error = %err, "panel user sync failed");
                    }
                    self.refresh_detect_rules().await;
                    self.expire_local_state();
                }
                _ = traffic.tick() => {
                    if let Err(err) = self.report_traffic().await {
                        warn!(error = %err, "traffic report failed; checkpoint not advanced");
                    }
                    if let Err(err) = self.report_auxiliary_state().await {
                        debug!(error = %err, "auxiliary state report failed");
                    }
                }
                _ = heartbeat.tick() => {
                    if let Err(err) = self.report_heartbeat().await {
                        debug!(error = %err, "heartbeat failed");
                    }
                }
            }
        }

        self.stop_all().await;
        Ok(())
    }

    async fn initial_panel_probe(&self) {
        if let Err(err) = self.panel.ping().await {
            warn!(error = %err, "panel ping failed");
        }
        match self.panel.node_info().await {
            Ok(Some(info)) => debug!(
                server = ?info.server,
                sort = ?info.sort,
                traffic_rate = ?info.traffic_rate,
                "loaded node info"
            ),
            Ok(None) => debug!("panel returned no node info"),
            Err(err) => debug!(error = %err, "node info probe failed"),
        }
        match self.panel.detect_rules().await {
            Ok(rules) => {
                for rule in rules {
                    debug!(id = rule.id, name = %rule.name, regex = %rule.regex, "loaded detect rule");
                }
            }
            Err(err) => debug!(error = %err, "detect rules probe failed"),
        }
        match self.panel.relay_rules().await {
            Ok(rules) => {
                for rule in rules {
                    debug!(
                        id = rule.id,
                        source_node_id = ?rule.source_node_id,
                        dist_node_id = ?rule.dist_node_id,
                        port = ?rule.port,
                        "loaded relay rule"
                    );
                }
            }
            Err(err) => debug!(error = %err, "relay rules probe failed"),
        }
    }

    async fn sync_users(&mut self) -> Result<()> {
        let users = self.panel.users().await?;
        if users.len() > self.config.limits.max_users {
            return Err(anyhow!(
                "panel returned {} users, over configured max_users={}",
                users.len(),
                self.config.limits.max_users
            ));
        }

        let mut live_user_ids = HashSet::new();
        let mut auth_users = HashMap::new();
        let mut counters_by_user = HashMap::new();
        let mut conns_by_user: HashMap<u64, Arc<AtomicUsize>> = HashMap::new();
        let mut speeds_by_user: HashMap<u64, Arc<RateLimiter>> = HashMap::new();
        let mut policies: HashMap<u64, Arc<UserPolicy>> = HashMap::new();

        for user in &users {
            let user_id = user.user_id();
            live_user_ids.insert(user_id);
            counters_by_user.insert(user_id, self.traffic.ensure_user(user_id));
            conns_by_user.insert(user_id, self.conns.ensure_user(user_id));
            let policy = UserPolicy::from_user(user);
            // Keep the per-user limiter in sync with the panel value (0 = unlimited
            // makes acquire a no-op); ensure_user updates an existing bucket's rate
            // in place so changes take effect without a listener restart.
            speeds_by_user.insert(
                user_id,
                self.speeds.ensure_user(user_id, policy.speed_limit_bps),
            );
            // Gate on connection-time controls only (conn limit / forbidden);
            // speed is handled live via SpeedLedger, so a speed-only change must
            // not add/remove this entry and flip the listener fingerprint.
            if policy.needs_connection_policy() {
                policies.insert(user_id, Arc::new(policy));
            }
            if user.is_multi_user == 0 {
                auth_users.insert(user_id, crate::ssr::derive_user_auth_key(&user.password));
            }
        }

        let auth_users_hash = hash_auth_users(&auth_users);
        let policies_hash = hash_policies(&policies);
        let auth_users = Arc::new(auth_users);
        let counters_by_user = Arc::new(counters_by_user);
        let conns_by_user = Arc::new(conns_by_user);
        let speeds_by_user = Arc::new(speeds_by_user);
        let policies = Arc::new(policies);
        let listener_users: Vec<PanelUser> = if users.iter().any(|user| user.is_multi_user != 0) {
            merge_carrier_users(
                users
                    .into_iter()
                    .filter(|user| user.is_multi_user != 0),
            )
        } else {
            users
                .into_iter()
                .filter(|user| user.is_multi_user == 0)
                .collect()
        };

        let mut live_ports = HashSet::new();
        for user in listener_users {
            let user_id = user.user_id();
            let profile = match Profile::from_user(&user, &self.config.node) {
                Ok(profile) => profile,
                Err(err) => {
                    warn!(user_id, port = user.port, error = %err, "skipping unsupported user profile");
                    continue;
                }
            };
            live_ports.insert(user.port);

            self.ensure_active_user(
                user,
                profile,
                auth_users.clone(),
                counters_by_user.clone(),
                conns_by_user.clone(),
                speeds_by_user.clone(),
                policies.clone(),
                auth_users_hash,
                policies_hash,
            )
            .await?;
        }

        let stale_ports: Vec<u16> = self
            .active_users
            .keys()
            .copied()
            .filter(|port| !live_ports.contains(port))
            .collect();
        for port in stale_ports {
            if let Some(active) = self.active_users.remove(&port) {
                info!(port, "removing stale port runtime state");
                active.stop().await;
            }
        }
        self.traffic.remove_stale_users(&live_user_ids);
        self.conns.remove_stale_users(&live_user_ids);
        self.speeds.remove_stale_users(&live_user_ids);
        self.sessions.retain(|key, _| live_user_ids.contains(&key.user_id));
        self.alive_ips.retain(|key, _| live_user_ids.contains(&key.user_id));
        self.detect_logs
            .retain(|key, _| live_user_ids.contains(&key.user_id));
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn ensure_active_user(
        &mut self,
        user: PanelUser,
        profile: Profile,
        auth_users: Arc<HashMap<u64, Vec<u8>>>,
        counters_by_user: Arc<HashMap<u64, std::sync::Arc<crate::traffic::UserCounters>>>,
        conns_by_user: Arc<HashMap<u64, Arc<AtomicUsize>>>,
        speeds_by_user: Arc<HashMap<u64, Arc<RateLimiter>>>,
        policies: Arc<HashMap<u64, Arc<UserPolicy>>>,
        auth_users_hash: u64,
        policies_hash: u64,
    ) -> Result<()> {
        let user_id = user.user_id();
        let fingerprint = UserFingerprint {
            port: user.port,
            password: user.password.clone(),
            profile: profile.clone(),
            is_multi_user: user.is_multi_user,
            auth_users_hash,
            policies_hash,
        };
        if matches!(self.active_users.get(&user.port), Some(active) if active.fingerprint == fingerprint)
        {
            return Ok(());
        }

        if let Some(active) = self.active_users.remove(&user.port) {
            info!(user_id, port = active.fingerprint.port, "restarting changed user runtime");
            active.stop().await;
        }

        let enforcement = EnforcementConfig {
            forbidden: self.config.node.enforce_forbidden,
            conn_limit: self.config.node.enforce_conn_limit,
            audit_block: self.config.node.audit_block,
            speed: self.config.node.enforce_speed,
        };
        let tcp = if self.config.node.tcp_enabled {
            Some(tcp::spawn_user_listener(
                self.config.node.listen_host.clone(),
                user_id,
                user.port,
                user.password.clone(),
                profile.clone(),
                auth_users.clone(),
                counters_by_user.clone(),
                conns_by_user.clone(),
                speeds_by_user.clone(),
                policies.clone(),
                enforcement,
                user.is_multi_user,
                self.config.limits.max_accepts_per_port,
                self.events_tx.clone(),
                self.detect_rules_rx.clone(),
            ))
        } else {
            None
        };
        let udp = if self.config.node.udp_enabled {
            Some(udp::spawn_user_listener(
                self.config.node.listen_host.clone(),
                user_id,
                user.port,
                user.password.clone(),
                profile,
                auth_users,
                counters_by_user,
                policies,
                enforcement,
                user.is_multi_user,
                self.config.limits.udp_association_ttl(),
                self.config.limits.max_udp_associations,
                self.events_tx.clone(),
                self.detect_rules_rx.clone(),
            ))
        } else {
            None
        };

        self.active_users.insert(user.port, ActiveUser { fingerprint, tcp, udp });
        Ok(())
    }

    async fn report_traffic(&self) -> Result<()> {
        let deltas = self.traffic.pending_deltas();
        if deltas.is_empty() {
            return Ok(());
        }
        self.panel.report_traffic(&deltas).await?;
        self.traffic.mark_reported(&deltas);
        Ok(())
    }

    async fn report_heartbeat(&self) -> Result<()> {
        let uptime = self.started_at.elapsed().as_secs();
        self.panel.report_node_info("0.00 0.00 0.00", uptime).await
    }

    async fn report_auxiliary_state(&mut self) -> Result<()> {
        let alive_ips: Vec<AliveIpReport> = self
            .alive_ips
            .keys()
            .map(|key| AliveIpReport {
                user_id: key.user_id,
                ip: key.ip.clone(),
            })
            .collect();
        self.panel.report_alive_ips(&alive_ips).await?;

        let detect_logs: Vec<DetectLogReport> = self.detect_logs.values().cloned().collect();
        if detect_logs.is_empty() {
            return Ok(());
        }
        self.panel.report_detect_logs(&detect_logs).await?;
        self.detect_logs.retain(|_, _| false);
        Ok(())
    }

    /// Record an audit event from a relay task into the bounded local maps.
    /// Inserts are deduped by the maps' keys, so repeated events for the same
    /// session / alive-IP / detect tuple coalesce.
    fn record_event(&mut self, event: RelayEvent) {
        match event {
            RelayEvent::Connect { user_id, ip, peer } => {
                self.sessions.insert(SessionKey { user_id, peer }, ());
                self.alive_ips.insert(AliveIpKey { user_id, ip }, ());
            }
            RelayEvent::Detect { user_id, list_id, ip } => {
                self.detect_logs.insert(
                    DetectLogKey {
                        user_id,
                        list_id,
                        ip,
                    },
                    DetectLogReport { user_id, list_id },
                );
            }
        }
    }

    /// Fetch the panel's detect rules, compile them, and publish the new rule set
    /// to every relay task over the watch channel. Best-effort: on fetch failure
    /// we keep the previously published rules.
    async fn refresh_detect_rules(&self) {
        match self.panel.detect_rules().await {
            Ok(rules) => {
                let compiled = audit::compile_rules(&rules);
                let count = compiled.len();
                if self.detect_rules_tx.send(compiled).is_ok() {
                    debug!(rules = count, "published detect rules to relay tasks");
                }
            }
            Err(err) => debug!(error = %err, "detect rules refresh failed; keeping current set"),
        }
    }

    fn expire_local_state(&mut self) {
        self.sessions.expire();
        self.alive_ips.expire();
        self.detect_logs.expire();
    }

    async fn stop_all(&mut self) {
        let active = std::mem::take(&mut self.active_users);
        for (_, user) in active {
            user.stop().await;
        }
    }
}

fn merge_carrier_users(users: impl Iterator<Item = PanelUser>) -> Vec<PanelUser> {
    let mut by_port = HashMap::<u16, PanelUser>::new();
    for user in users {
        match by_port.get(&user.port) {
            Some(existing) if carrier_config_matches(existing, &user) => {
                debug!(
                    port = user.port,
                    kept_user_id = existing.user_id(),
                    skipped_user_id = user.user_id(),
                    "merged duplicate carrier row with identical endpoint config"
                );
            }
            Some(existing) => {
                warn!(
                    port = user.port,
                    kept_user_id = existing.user_id(),
                    skipped_user_id = user.user_id(),
                    "carrier rows share a port but have different endpoint config; keeping first row"
                );
            }
            None => {
                by_port.insert(user.port, user);
            }
        }
    }
    by_port.into_values().collect()
}

fn carrier_config_matches(a: &PanelUser, b: &PanelUser) -> bool {
    a.port == b.port
        && a.password == b.password
        && a.method == b.method
        && a.protocol == b.protocol
        && a.protocol_param == b.protocol_param
        && a.obfs == b.obfs
        && a.obfs_param == b.obfs_param
        && a.is_multi_user == b.is_multi_user
}

/// Wait for an OS shutdown signal.
///
/// systemd's `systemctl stop` sends SIGTERM (not SIGINT), so we must listen for
/// both on Unix or the process would never run its graceful `stop_all()` and
/// would instead be SIGKILLed after the stop timeout. On non-Unix targets
/// (local dev on Windows) we fall back to Ctrl-C.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match (signal(SignalKind::terminate()), signal(SignalKind::interrupt())) {
            (Ok(mut term), Ok(mut int)) => {
                tokio::select! {
                    _ = term.recv() => info!("received SIGTERM"),
                    _ = int.recv() => info!("received SIGINT"),
                }
            }
            (Ok(mut term), Err(err)) => {
                warn!(error = %err, "failed to install SIGINT handler; SIGTERM only");
                term.recv().await;
            }
            (Err(err), _) => {
                warn!(error = %err, "failed to install SIGTERM handler; falling back to Ctrl-C");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        info!("received Ctrl-C");
    }
}
