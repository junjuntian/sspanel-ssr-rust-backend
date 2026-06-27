use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    net::{lookup_host, UdpSocket},
    sync::oneshot,
    task::JoinHandle,
};
use tracing::{debug, error, info, warn};

use crate::{
    audit::{self, EventSender, RuleWatch},
    policy::{EnforcementConfig, UserPolicy},
    runtime::state::BoundedTtlMap,
    ssr,
    ssr::{Address, CipherKind, Profile},
    traffic::UserCounters,
};

/// Max UDP datagram we will read. SSR datagrams are well under this.
const BUF_SIZE: usize = 64 * 1024;

pub struct UdpListenerTask {
    stop: Option<oneshot::Sender<()>>,
    join: JoinHandle<()>,
}

impl UdpListenerTask {
    pub async fn stop(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), self.join).await;
    }
}

/// One client peer's outbound UDP socket plus the task that pumps responses back.
/// Dropping it (TTL eviction, capacity eviction, or listener shutdown) aborts the
/// pump task and closes the socket via RAII.
struct Association {
    outbound: Arc<UdpSocket>,
    pump: JoinHandle<()>,
}

impl Drop for Association {
    fn drop(&mut self) {
        self.pump.abort();
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct AssociationKey {
    peer: SocketAddr,
    user_id: u64,
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_user_listener(
    listen_host: String,
    user_id: u64,
    port: u16,
    password: String,
    profile: Profile,
    auth_users: Arc<HashMap<u64, Vec<u8>>>,
    counters_by_user: Arc<HashMap<u64, Arc<UserCounters>>>,
    policies: Arc<HashMap<u64, Arc<UserPolicy>>>,
    enforcement: EnforcementConfig,
    is_multi_user: i64,
    association_ttl: Duration,
    max_associations: usize,
    events: EventSender,
    rules: RuleWatch,
) -> UdpListenerTask {
    let (stop_tx, stop_rx) = oneshot::channel();
    let join = tokio::spawn(async move {
        if let Err(err) = run_listener(
            listen_host,
            user_id,
            port,
            password,
            profile,
            auth_users,
            counters_by_user,
            policies,
            enforcement,
            is_multi_user,
            association_ttl,
            max_associations.max(1),
            events,
            rules,
            stop_rx,
        )
        .await
        {
            error!(user_id, port, error = %err, "udp listener stopped with error");
        }
    });
    UdpListenerTask {
        stop: Some(stop_tx),
        join,
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_listener(
    listen_host: String,
    user_id: u64,
    port: u16,
    password: String,
    profile: Profile,
    auth_users: Arc<HashMap<u64, Vec<u8>>>,
    counters_by_user: Arc<HashMap<u64, Arc<UserCounters>>>,
    policies: Arc<HashMap<u64, Arc<UserPolicy>>>,
    enforcement: EnforcementConfig,
    is_multi_user: i64,
    association_ttl: Duration,
    max_associations: usize,
    events: EventSender,
    rules: RuleWatch,
    mut stop: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let address = format!("{listen_host}:{port}");
    let socket = Arc::new(UdpSocket::bind(&address).await?);
    let cipher_kind = profile.cipher_kind();
    let master_key = Arc::new(ssr::derive_master_key(&password, cipher_kind));
    let mut associations =
        BoundedTtlMap::<AssociationKey, Association>::new(association_ttl, max_associations);
    let mut buffer = vec![0_u8; BUF_SIZE];
    info!(
        user_id,
        port,
        method = %profile.method,
        protocol = %profile.protocol,
        obfs = %profile.obfs,
        "udp listener started"
    );

    loop {
        tokio::select! {
            biased;
            _ = &mut stop => {
                info!(user_id, port, "udp listener stopping");
                break;
            }
            received = socket.recv_from(&mut buffer) => {
                let (size, peer) = received?;
                associations.expire();

                if let Err(err) = handle_inbound(
                    &buffer[..size],
                    peer,
                    user_id,
                    port,
                    &master_key,
                    &auth_users,
                    &policies,
                    enforcement,
                    &socket,
                    &counters_by_user,
                    is_multi_user,
                    cipher_kind,
                    &mut associations,
                    max_associations,
                    &events,
                    &rules,
                )
                .await
                {
                    debug!(user_id, port, %peer, error = %err, "udp datagram dropped");
                }
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_inbound(
    datagram: &[u8],
    peer: SocketAddr,
    user_id: u64,
    port: u16,
    master_key: &Arc<Vec<u8>>,
    auth_users: &Arc<HashMap<u64, Vec<u8>>>,
    policies: &Arc<HashMap<u64, Arc<UserPolicy>>>,
    enforcement: EnforcementConfig,
    server_socket: &Arc<UdpSocket>,
    counters_by_user: &Arc<HashMap<u64, Arc<UserCounters>>>,
    is_multi_user: i64,
    cipher_kind: CipherKind,
    associations: &mut BoundedTtlMap<AssociationKey, Association>,
    max_associations: usize,
    events: &EventSender,
    rules: &RuleWatch,
) -> anyhow::Result<()> {
    let (plain, authenticated_user_id) =
        ssr::udp_decrypt_packet(master_key, auth_users, is_multi_user, datagram, cipher_kind)?;
    let real_user_id = authenticated_user_id.unwrap_or(user_id);
    // The server->client response HMAC must be keyed by the authenticated user's
    // key (md5(password)) in single-port multi-user mode; in normal mode there is
    // no per-user entry and we fall back to the carrier master key.
    let response_key: Arc<Vec<u8>> = match authenticated_user_id {
        Some(uid) => auth_users
            .get(&uid)
            .cloned()
            .map(Arc::new)
            .unwrap_or_else(|| master_key.clone()),
        None => master_key.clone(),
    };
    let counters = counters_by_user
        .get(&real_user_id)
        .cloned()
        .or_else(|| counters_by_user.get(&user_id).cloned())
        .ok_or_else(|| anyhow::anyhow!("no traffic counter for UDP user {real_user_id}"))?;
    counters.record_upload(datagram.len() as u64);
    let Some((target, consumed)) = ssr::parse_address(&plain)? else {
        anyhow::bail!("udp address header incomplete");
    };
    let payload = &plain[consumed..];

    // Per-user enforcement policy (present only for users with active limits).
    let policy = policies.get(&real_user_id);
    if enforcement.forbidden {
        if let Some(policy) = policy {
            if policy.port_forbidden(target.port) {
                anyhow::bail!("udp target port {} forbidden for user {real_user_id}", target.port);
            }
        }
    }

    // Audit the decrypted payload against detect rules (deduped downstream by the
    // supervisor's detect-log map; try_send drops under pressure). When node-side
    // audit blocking is on, a match drops the datagram before it is relayed.
    let ip = peer.ip().to_string();
    let matched = audit::scan_payload(&rules.borrow(), events, real_user_id, &ip, payload);
    if matched && enforcement.audit_block {
        anyhow::bail!("udp datagram dropped: payload matched a detect rule");
    }

    // Resolve + forbidden-IP filter the destination. Without an active
    // forbidden-IP list we keep the original (host, port) send path unchanged.
    let dest = resolve_udp_dest(&target, policy.map(|p| p.as_ref()), enforcement).await?;

    // Reuse this peer's outbound socket, or create one (binding is async, so we
    // can't do it inside the map's insert closure).
    let association_key = AssociationKey {
        peer,
        user_id: real_user_id,
    };
    let outbound = match associations.touch(&association_key).map(|a| a.outbound.clone()) {
        Some(outbound) => outbound,
        None => {
            if associations.len() >= max_associations {
                warn!(
                    user_id,
                    port,
                    associations = associations.len(),
                    "udp association capacity reached; evicting oldest"
                );
            }
            // First datagram from this peer: record the session / alive-IP.
            audit::report_connect(events, real_user_id, &ip, &peer.to_string());
            let outbound = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
            let pump = spawn_response_pump(
                outbound.clone(),
                server_socket.clone(),
                master_key.clone(),
                response_key,
                counters,
                peer,
                cipher_kind,
            );
            associations.insert(association_key, Association { outbound: outbound.clone(), pump });
            outbound
        }
    };

    match dest {
        UdpDest::Addr(addr) => {
            outbound.send_to(payload, addr).await?;
        }
        UdpDest::HostPort(host, port) => {
            outbound.send_to(payload, (host.as_str(), port)).await?;
        }
    }
    Ok(())
}

/// Where a UDP datagram should be forwarded after policy checks.
enum UdpDest {
    /// A concrete, forbidden-IP-checked socket address.
    Addr(SocketAddr),
    /// The original target host/port (no forbidden-IP list active); resolution is
    /// left to the OS on send, preserving the pre-policy behavior.
    HostPort(String, u16),
}

/// Resolve and forbidden-IP-filter a UDP target. When the user has no active
/// forbidden-IP list we skip resolution and keep the original (host, port) path.
async fn resolve_udp_dest(
    target: &Address,
    policy: Option<&UserPolicy>,
    enforcement: EnforcementConfig,
) -> anyhow::Result<UdpDest> {
    let ip_check = enforcement.forbidden && policy.is_some_and(UserPolicy::has_forbidden_ip);
    if !ip_check {
        return Ok(UdpDest::HostPort(target.host.clone(), target.port));
    }
    let policy = policy.expect("ip_check implies policy present");
    let resolved: Vec<SocketAddr> = lookup_host((target.host.as_str(), target.port))
        .await
        .map_err(|err| anyhow::anyhow!("resolving {}:{}: {err}", target.host, target.port))?
        .collect();
    if resolved.is_empty() {
        anyhow::bail!("udp target {}:{} did not resolve", target.host, target.port);
    }
    let allowed = resolved
        .into_iter()
        .find(|addr| !policy.ip_forbidden(addr.ip()));
    match allowed {
        Some(addr) => Ok(UdpDest::Addr(addr)),
        None => anyhow::bail!(
            "udp target {}:{} resolves only to forbidden addresses",
            target.host,
            target.port
        ),
    }
}

/// Pump target responses on `outbound` back to the client `peer`, re-encrypting
/// each datagram with its origin address header.
fn spawn_response_pump(
    outbound: Arc<UdpSocket>,
    server_socket: Arc<UdpSocket>,
    master_key: Arc<Vec<u8>>,
    response_key: Arc<Vec<u8>>,
    counters: Arc<UserCounters>,
    peer: SocketAddr,
    cipher_kind: CipherKind,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0_u8; BUF_SIZE];
        loop {
            let (n, from) = match outbound.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            let mut header = ssr::pack_socket_addr(from.ip(), from.port());
            header.extend_from_slice(&buf[..n]);
            match ssr::udp_encrypt_packet(&master_key, &response_key, &header, cipher_kind) {
                Ok(pkt) => {
                    counters.record_download(pkt.len() as u64);
                    if server_socket.send_to(&pkt, peer).await.is_err() {
                        break;
                    }
                }
                Err(_) => continue,
            }
        }
    })
}
