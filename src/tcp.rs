use std::{net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{lookup_host, TcpListener, TcpStream},
    sync::{oneshot, Semaphore},
    task::JoinHandle,
    time::{self, Instant},
};
use tracing::{debug, error, info, warn};

use crate::{
    audit::{ConnectionAuditor, EventSender, RuleWatch},
    policy::{EnforcementConfig, UserPolicy},
    ssr::{self, Address, CipherKind, Profile, ServerSession},
    traffic::ConnGuard,
    user_tables::{UserTables, UserTablesWatch},
};

/// Max bytes pulled from a socket per read. Also caps how much app payload we
/// buffer while waiting for the address header to complete.
const READ_CHUNK: usize = 16 * 1024;
/// Hard cap on un-parsed handshake payload, so a malformed client cannot make us
/// buffer without bound before the address header is complete.
const MAX_HANDSHAKE_BYTES: usize = 64 * 1024;

struct StreamContext {
    password: String,
    fallback_user_id: u64,
    /// Snapshot of the per-user tables taken at accept time. Cheap to clone
    /// (Arc fields) and stable for the lifetime of this one connection, so a
    /// later panel poll that swaps the published tables never affects an
    /// in-flight session.
    tables: Arc<UserTables>,
    enforcement: EnforcementConfig,
    is_multi_user: i64,
    cipher_kind: CipherKind,
    events: EventSender,
    rules: RuleWatch,
    peer_ip: String,
    peer: String,
    idle_timeout: Duration,
}

pub struct TcpListenerTask {
    stop: Option<oneshot::Sender<()>>,
    join: JoinHandle<()>,
}

impl TcpListenerTask {
    pub async fn stop(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), self.join).await;
    }
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_user_listener(
    listen_host: String,
    user_id: u64,
    port: u16,
    password: String,
    profile: Profile,
    tables_rx: UserTablesWatch,
    enforcement: EnforcementConfig,
    is_multi_user: i64,
    max_accepts: usize,
    events: EventSender,
    rules: RuleWatch,
) -> TcpListenerTask {
    let (stop_tx, stop_rx) = oneshot::channel();
    let join = tokio::spawn(async move {
        if let Err(err) = run_listener(
            listen_host,
            user_id,
            port,
            password,
            profile,
            tables_rx,
            enforcement,
            is_multi_user,
            max_accepts.max(1),
            events,
            rules,
            stop_rx,
        )
        .await
        {
            error!(user_id, port, error = %err, "tcp listener stopped with error");
        }
    });
    TcpListenerTask {
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
    tables_rx: UserTablesWatch,
    enforcement: EnforcementConfig,
    is_multi_user: i64,
    max_accepts: usize,
    events: EventSender,
    rules: RuleWatch,
    mut stop: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let address = format!("{listen_host}:{port}");
    let listener = TcpListener::bind(&address).await?;
    let permits = Arc::new(Semaphore::new(max_accepts));
    let cipher_kind = profile.cipher_kind();
    info!(
        user_id,
        port,
        method = %profile.method,
        protocol = %profile.protocol,
        obfs = %profile.obfs,
        "tcp listener started"
    );

    loop {
        tokio::select! {
            biased;
            _ = &mut stop => {
                info!(user_id, port, "tcp listener stopping");
                break;
            }
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    warn!(user_id, port, %peer, "tcp accept capacity reached; closing connection");
                    continue;
                };
                // Snapshot the current per-user tables for this connection. Reading
                // the watch synchronously here (no await held across the borrow)
                // picks up the latest panel poll without any listener restart.
                let tables = tables_rx.borrow().clone();
                let password = password.clone();
                let session_timeout = profile.timeout;
                let events = events.clone();
                let rules = rules.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let context = StreamContext {
                        password,
                        fallback_user_id: user_id,
                        tables,
                        enforcement,
                        is_multi_user,
                        cipher_kind,
                        events,
                        rules,
                        peer_ip: peer.ip().to_string(),
                        peer: peer.to_string(),
                        idle_timeout: session_timeout,
                    };
                    match handle_stream(stream, context).await {
                        Ok(()) => {}
                        Err(err) => debug!(user_id, port, %peer, error = %err, "tcp session closed"),
                    }
                });
            }
        }
    }
    Ok(())
}

async fn handle_stream(
    stream: TcpStream,
    context: StreamContext,
) -> anyhow::Result<()> {
    stream.set_nodelay(true).ok();
    let mut session = ServerSession::new(
        &context.password,
        context.tables.auth_users.clone(),
        context.is_multi_user,
        context.cipher_kind,
    )?;
    let (mut client_read, mut client_write) = stream.into_split();

    // --- Handshake: decode until the SSR address header is complete. ---
    let mut app_buf: Vec<u8> = Vec::new();
    let mut chunk = vec![0_u8; READ_CHUNK];
    let mut pre_auth_upload = 0_u64;
    let (target, initial) = loop {
        let n = time::timeout(context.idle_timeout, client_read.read(&mut chunk))
            .await
            .map_err(|_| anyhow::anyhow!("ssr handshake idle timeout after {:?}", context.idle_timeout))??;
        if n == 0 {
            return Ok(()); // client closed before completing the handshake
        }
        pre_auth_upload = pre_auth_upload.saturating_add(n as u64);
        let decoded = session.decrypt(&chunk[..n])?;
        if decoded.is_empty() {
            continue;
        }
        app_buf.extend_from_slice(&decoded);
        if let Some((addr, consumed)) = ssr::parse_address(&app_buf)? {
            let initial = app_buf.split_off(consumed);
            break (addr, initial);
        }
        if app_buf.len() > MAX_HANDSHAKE_BYTES {
            anyhow::bail!("ssr handshake exceeded {MAX_HANDSHAKE_BYTES} bytes without a valid address");
        }
    };

    let user_id = session.user_id().unwrap_or(context.fallback_user_id);
    let counters = context.tables.counters_by_user
        .get(&user_id)
        .cloned()
        .or_else(|| context.tables.counters_by_user.get(&context.fallback_user_id).cloned())
        .ok_or_else(|| anyhow::anyhow!("no traffic counter for authenticated user {user_id}"))?;
    counters.record_upload(pre_auth_upload);

    // Per-user enforcement policy (present only for users with active limits).
    let policy = context.tables.policies.get(&user_id).cloned();

    // node_speedlimit: shared per-user token bucket. `None` => unlimited (the
    // limiter is a no-op anyway when rate==0, but skipping the await avoids the
    // lock entirely on the hot path for unlimited users).
    let limiter = if context.enforcement.speed {
        context.tables.speeds_by_user.get(&user_id).cloned()
    } else {
        None
    };

    // node_connector: cap concurrent connections per user. The guard lives for
    // the whole session and decrements on drop (close/error/abort).
    let _conn_guard = match (&policy, context.enforcement.conn_limit) {
        (Some(policy), true) if policy.conn_limit > 0 => {
            let counter = context
                .tables
                .conns_by_user
                .get(&user_id)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no connection counter for user {user_id}"))?;
            match ConnGuard::acquire(counter, policy.conn_limit) {
                Some(guard) => Some(guard),
                None => {
                    debug!(user_id, limit = policy.conn_limit, "connection limit reached; dropping");
                    return Ok(());
                }
            }
        }
        _ => None,
    };

    let mut auditor = ConnectionAuditor::new(
        user_id,
        context.peer_ip,
        context.peer,
        context.events,
        context.rules,
    );

    // Handshake succeeded: this is an authenticated SSR client. Record the
    // session / alive-IP, and audit the initial payload.
    auditor.report_connect();
    if auditor.scan(&initial) && context.enforcement.audit_block {
        anyhow::bail!("connection dropped: initial payload matched a detect rule");
    }

    // --- Connect to the requested target, enforcing forbidden_ip/port. ---
    let remote = connect_target_checked(&target, policy.as_deref(), context.enforcement).await?;
    remote.set_nodelay(true).ok();
    let (mut remote_read, mut remote_write) = remote.into_split();
    if !initial.is_empty() {
        if let Some(l) = &limiter {
            l.acquire(initial.len()).await;
        }
        remote_write.write_all(&initial).await?;
    }

    // --- Bidirectional relay in a single task so the codec is only ever
    //     borrowed by one direction at a time (encrypt/decrypt are disjoint
    //     state, but live in one `session`). ---
    let mut from_client = vec![0_u8; READ_CHUNK];
    let mut from_remote = vec![0_u8; READ_CHUNK];
    let idle = time::sleep(context.idle_timeout);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            _ = &mut idle => {
                anyhow::bail!("tcp session idle timeout after {:?}", context.idle_timeout);
            }
            r = client_read.read(&mut from_client) => {
                let n = r?;
                if n == 0 {
                    break;
                }
                idle.as_mut().reset(Instant::now() + context.idle_timeout);
                counters.record_upload(n as u64);
                let data = session.decrypt(&from_client[..n])?;
                if !data.is_empty() {
                    // Detect rules are enforced ONLY on the handshake/initial
                    // payload (target address + first request line / TLS SNI / BT
                    // handshake), mirroring the original SSR audit intent. The
                    // streaming body is deliberately NOT scanned or blocked here:
                    // the panel rule set matches target domains / request
                    // signatures, and applying it per-chunk to arbitrary upload
                    // bytes produced false positives (e.g. the BT rule's
                    // `tracker|seed|ratio|p2p` words appearing inside ordinary
                    // file data) that broke normal uploads. First-packet blocking
                    // above still stops BT handshakes and forbidden domains.
                    if let Some(l) = &limiter {
                        l.acquire(data.len()).await;
                    }
                    time::timeout(context.idle_timeout, remote_write.write_all(&data))
                        .await
                        .map_err(|_| anyhow::anyhow!("remote write idle timeout after {:?}", context.idle_timeout))??;
                }
            }
            r = remote_read.read(&mut from_remote) => {
                let n = r?;
                if n == 0 {
                    break;
                }
                idle.as_mut().reset(Instant::now() + context.idle_timeout);
                let wire = session.encrypt(&from_remote[..n])?;
                counters.record_download(wire.len() as u64);
                if let Some(l) = &limiter {
                    l.acquire(wire.len()).await;
                }
                time::timeout(context.idle_timeout, client_write.write_all(&wire))
                    .await
                    .map_err(|_| anyhow::anyhow!("client write idle timeout after {:?}", context.idle_timeout))??;
            }
        }
    }

    let _ = remote_write.shutdown().await;
    let _ = client_write.shutdown().await;
    Ok(())
}

/// Connect to `target`, enforcing the user's `forbidden_port` / `forbidden_ip`
/// policy. When a forbidden-IP list is active we resolve the target first and
/// refuse to connect to any address that falls inside it (this also catches
/// domains that resolve into a forbidden range, e.g. `localhost` -> 127.0.0.1).
async fn connect_target_checked(
    target: &Address,
    policy: Option<&UserPolicy>,
    enforcement: EnforcementConfig,
) -> anyhow::Result<TcpStream> {
    let (host, port) = target.connect_target();

    if enforcement.forbidden {
        if let Some(policy) = policy {
            if policy.port_forbidden(port) {
                anyhow::bail!("target port {port} is forbidden for this user");
            }
        }
    }

    let ip_check = enforcement.forbidden && policy.is_some_and(UserPolicy::has_forbidden_ip);
    if !ip_check {
        return Ok(TcpStream::connect((host.as_str(), port)).await?);
    }

    let policy = policy.expect("ip_check implies policy present");
    let resolved: Vec<SocketAddr> = lookup_host((host.as_str(), port))
        .await
        .map_err(|err| anyhow::anyhow!("resolving {host}:{port}: {err}"))?
        .collect();
    if resolved.is_empty() {
        anyhow::bail!("target {host}:{port} did not resolve");
    }
    let allowed: Vec<SocketAddr> = resolved
        .into_iter()
        .filter(|addr| !policy.ip_forbidden(addr.ip()))
        .collect();
    if allowed.is_empty() {
        anyhow::bail!("target {host}:{port} resolves only to forbidden addresses");
    }

    let mut last_err = None;
    for addr in allowed {
        match TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = Some(err),
        }
    }
    Err(anyhow::anyhow!(
        "connecting to {host}:{port}: {}",
        last_err.expect("non-empty allowed list yields an error on failure")
    ))
}
