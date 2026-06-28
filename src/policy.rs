//! Per-user enforcement policy derived from the panel's user rows.
//!
//! SSPanel ships a handful of node-side controls per user that the original
//! Python `Mod_Mu` runtime enforced inline on the relay path. We mirror the ones
//! that are observable on the wire:
//!   * `forbidden_ip`   — comma-separated IP/CIDR list the user may not reach;
//!   * `forbidden_port` — comma-separated port / port-range list, likewise;
//!   * `node_connector` — max distinct client IPs (devices) the user may connect
//!     from concurrently (0 = off). Note: this is a device/IP cap, not a raw
//!     concurrent-connection cap — one IP may hold many connections;
//!   * `node_speedlimit`— Mbit/s rate cap (0 = off). Parsed here; the token-bucket
//!     enforcement lives on the relay path.
//!
//! In single-port multi-user mode the policy that matters is the *authenticated*
//! real user's (identified by the uid in the auth header), not the carrier's.

use std::net::{IpAddr, Ipv4Addr};

use crate::panel::PanelUser;

/// Which node-side controls the relay path should actually enforce. Mirrors the
/// `[node]` kill switches so an operator can disable any of them without a code
/// change (keeps the "无感" escape hatch).
#[derive(Debug, Clone, Copy)]
pub struct EnforcementConfig {
    pub forbidden: bool,
    pub conn_limit: bool,
    pub audit_block: bool,
    pub speed: bool,
}

/// One CIDR block. A bare address parses as a host route (/32 or /128).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Cidr {
    base: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parse `"127.0.0.0/8"`, `"::1/128"`, or a bare `"1.2.3.4"` / `"::1"`.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        if text.is_empty() {
            return None;
        }
        let (addr_part, prefix_part) = match text.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (text, None),
        };
        let base: IpAddr = addr_part.trim().parse().ok()?;
        let max = if base.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_part {
            Some(p) => {
                let n: u8 = p.trim().parse().ok()?;
                if n > max {
                    return None;
                }
                n
            }
            None => max,
        };
        Some(Self { base, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.base, ip) {
            (IpAddr::V4(base), IpAddr::V4(ip)) => {
                v4_in(u32::from(base), u32::from(ip), self.prefix)
            }
            (IpAddr::V6(base), IpAddr::V6(ip)) => {
                v6_in(u128::from(base), u128::from(ip), self.prefix)
            }
            // An IPv4-mapped IPv6 target (::ffff:a.b.c.d) should still match an
            // IPv4 forbidden rule, and vice-versa.
            (IpAddr::V4(base), IpAddr::V6(ip)) => match ip.to_ipv4_mapped() {
                Some(ip4) => v4_in(u32::from(base), u32::from(ip4), self.prefix),
                None => false,
            },
            (IpAddr::V6(base), IpAddr::V4(ip)) => {
                let mapped = Ipv4Addr::from(ip).to_ipv6_mapped();
                v6_in(u128::from(base), u128::from(mapped), self.prefix)
            }
        }
    }
}

fn v4_in(base: u32, ip: u32, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask = u32::MAX << (32 - prefix);
    (base & mask) == (ip & mask)
}

fn v6_in(base: u128, ip: u128, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask = u128::MAX << (128 - prefix);
    (base & mask) == (ip & mask)
}

/// An inclusive port range. A bare `"443"` parses as `(443, 443)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortRange {
    start: u16,
    end: u16,
}

impl PortRange {
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        if text.is_empty() {
            return None;
        }
        if let Some((a, b)) = text.split_once('-') {
            let start: u16 = a.trim().parse().ok()?;
            let end: u16 = b.trim().parse().ok()?;
            let (start, end) = if start <= end { (start, end) } else { (end, start) };
            Some(Self { start, end })
        } else {
            let p: u16 = text.parse().ok()?;
            Some(Self { start: p, end: p })
        }
    }

    pub fn contains(&self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
}

/// Per-user enforcement knobs. `Default` = no limits.
///
/// Derives `Hash`/`Eq` so the supervisor can fold it into a listener fingerprint
/// and restart the listener only when a user's policy actually changes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct UserPolicy {
    /// Rate cap in bytes/sec. 0 = unlimited.
    pub speed_limit_bps: u64,
    /// Max distinct client IPs (devices) connected at once. 0 = unlimited.
    pub conn_limit: u32,
    pub forbidden_ips: Vec<Cidr>,
    pub forbidden_ports: Vec<PortRange>,
}

impl UserPolicy {
    pub fn from_user(user: &PanelUser) -> Self {
        let mbits = user.node_speedlimit.unwrap_or(0.0).max(0.0);
        // Mbit/s -> bytes/s.
        let speed_limit_bps = (mbits * 1024.0 * 1024.0 / 8.0) as u64;
        let conn_limit = user.node_connector.unwrap_or(0).max(0) as u32;
        let forbidden_ips = parse_list(user.forbidden_ip.as_deref(), Cidr::parse);
        let forbidden_ports = parse_list(user.forbidden_port.as_deref(), PortRange::parse);
        Self {
            speed_limit_bps,
            conn_limit,
            forbidden_ips,
            forbidden_ports,
        }
    }

    pub fn is_unrestricted(&self) -> bool {
        self.speed_limit_bps == 0
            && self.conn_limit == 0
            && self.forbidden_ips.is_empty()
            && self.forbidden_ports.is_empty()
    }

    /// Whether the relay listener needs a captured policy entry for this user —
    /// i.e. there is a *connection-time* control to enforce (conn limit or a
    /// forbidden ip/port). Speed is deliberately excluded: the rate cap is
    /// applied through the shared, live-updated `SpeedLedger`, not the listener's
    /// captured policy snapshot. Gating policy-map membership on this (instead of
    /// `!is_unrestricted()`) keeps a speed-only change from adding/removing the
    /// user from the map — which would flip the listener fingerprint and force a
    /// needless restart (dropping the accept loop for every user on a single-port
    /// carrier). Keeping it speed-independent makes speed changes 无感.
    pub fn needs_connection_policy(&self) -> bool {
        self.conn_limit > 0
            || !self.forbidden_ips.is_empty()
            || !self.forbidden_ports.is_empty()
    }

    pub fn port_forbidden(&self, port: u16) -> bool {
        self.forbidden_ports.iter().any(|r| r.contains(port))
    }

    pub fn ip_forbidden(&self, ip: IpAddr) -> bool {
        self.forbidden_ips.iter().any(|c| c.contains(ip))
    }

    pub fn has_forbidden_ip(&self) -> bool {
        !self.forbidden_ips.is_empty()
    }
}

fn parse_list<T>(raw: Option<&str>, parse: impl Fn(&str) -> Option<T>) -> Vec<T> {
    let Some(raw) = raw else { return Vec::new() };
    raw.split(',')
        .filter_map(|item| {
            let item = item.trim();
            if item.is_empty() {
                None
            } else {
                parse(item)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn cidr_v4_contains() {
        let c = Cidr::parse("127.0.0.0/8").unwrap();
        assert!(c.contains(ip("127.0.0.1")));
        assert!(c.contains(ip("127.255.255.254")));
        assert!(!c.contains(ip("126.255.255.255")));
        assert!(!c.contains(ip("128.0.0.0")));
    }

    #[test]
    fn cidr_bare_host() {
        let c = Cidr::parse("1.2.3.4").unwrap();
        assert!(c.contains(ip("1.2.3.4")));
        assert!(!c.contains(ip("1.2.3.5")));
    }

    #[test]
    fn cidr_v6_loopback() {
        let c = Cidr::parse("::1/128").unwrap();
        assert!(c.contains(ip("::1")));
        assert!(!c.contains(ip("::2")));
    }

    #[test]
    fn cidr_v4_mapped_matches_v4_rule() {
        let c = Cidr::parse("127.0.0.0/8").unwrap();
        assert!(c.contains(ip("::ffff:127.0.0.1")));
    }

    #[test]
    fn port_range() {
        let r = PortRange::parse("1000-2000").unwrap();
        assert!(r.contains(1000));
        assert!(r.contains(2000));
        assert!(!r.contains(999));
        assert!(!r.contains(2001));
        let single = PortRange::parse("25").unwrap();
        assert!(single.contains(25));
        assert!(!single.contains(26));
    }

    #[test]
    fn policy_from_panel_loopback_block() {
        let user = PanelUser {
            id: 1477,
            user_id: None,
            port: 558,
            password: "x".into(),
            method: None,
            protocol: None,
            protocol_param: None,
            obfs: None,
            obfs_param: None,
            enable: Some(1),
            is_multi_user: 0,
            node_speedlimit: Some(0.0),
            node_connector: Some(4),
            forbidden_ip: Some("127.0.0.0/8,::1/128".into()),
            forbidden_port: Some(String::new()),
        };
        let p = UserPolicy::from_user(&user);
        assert_eq!(p.conn_limit, 4);
        assert_eq!(p.speed_limit_bps, 0);
        assert!(p.ip_forbidden(ip("127.0.0.1")));
        assert!(p.ip_forbidden(ip("::1")));
        assert!(!p.ip_forbidden(ip("8.8.8.8")));
        assert!(!p.is_unrestricted());
    }

    #[test]
    fn speed_only_needs_no_connection_policy() {
        // A user with only a speed cap must NOT require a listener policy entry:
        // speed is applied via SpeedLedger, and gating membership on speed would
        // churn the listener fingerprint on every speed change.
        let p = UserPolicy::from_user(&base_user_with_speed(5.0));
        assert!(!p.is_unrestricted(), "speed cap means not fully unrestricted");
        assert!(
            !p.needs_connection_policy(),
            "speed-only must not need a connection policy entry"
        );

        // But a conn limit or forbidden list must require an entry.
        let mut u = base_user_with_speed(0.0);
        u.node_connector = Some(3);
        assert!(UserPolicy::from_user(&u).needs_connection_policy());

        let mut u2 = base_user_with_speed(0.0);
        u2.forbidden_ip = Some("10.0.0.0/8".into());
        assert!(UserPolicy::from_user(&u2).needs_connection_policy());
    }

    #[test]
    fn speed_mbit_to_bytes() {
        let user = base_user_with_speed(1.0);
        let p = UserPolicy::from_user(&user);
        assert_eq!(p.speed_limit_bps, 131072); // 1 Mbit/s = 131072 B/s
    }

    fn base_user_with_speed(mbit: f64) -> PanelUser {
        PanelUser {
            id: 1,
            user_id: None,
            port: 1,
            password: "x".into(),
            method: None,
            protocol: None,
            protocol_param: None,
            obfs: None,
            obfs_param: None,
            enable: Some(1),
            is_multi_user: 0,
            node_speedlimit: Some(mbit),
            node_connector: Some(0),
            forbidden_ip: None,
            forbidden_port: None,
        }
    }
}
