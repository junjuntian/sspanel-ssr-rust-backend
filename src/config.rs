use std::{fs, path::Path, time::Duration};

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub panel: PanelConfig,
    pub node: NodeConfig,
    pub limits: LimitsConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PanelConfig {
    pub base_url: String,
    pub key: String,
    pub node_id: u64,
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,
    #[serde(default = "default_poll_interval_secs")]
    pub poll_interval_secs: u64,
    #[serde(default = "default_traffic_report_interval_secs")]
    pub traffic_report_interval_secs: u64,
    #[serde(default = "default_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,
    /// Force IPv4 for panel webapi requests. SSPanel's checkNodeIp matches the
    /// request source IP against the node's IPv4 `server` field; on an
    /// IPv6-capable host the panel would otherwise reject with "IP is invalid".
    /// Leave true unless the node is registered in the panel by IPv6.
    #[serde(default = "default_true")]
    pub ipv4_only: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NodeConfig {
    #[serde(default = "default_listen_host")]
    pub listen_host: String,
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(default = "default_obfs")]
    pub obfs: String,
    #[serde(default = "default_server_port")]
    pub server_port: u16,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default = "default_workers")]
    pub workers: usize,
    #[serde(default = "default_true")]
    pub tcp_enabled: bool,
    #[serde(default = "default_true")]
    pub udp_enabled: bool,
    /// Enforce per-user `forbidden_ip` / `forbidden_port` (drop matching targets).
    /// Kill switch: set false to relay regardless of the panel's forbidden lists.
    #[serde(default = "default_true")]
    pub enforce_forbidden: bool,
    /// Enforce per-user `node_connector` concurrent-connection cap.
    #[serde(default = "default_true")]
    pub enforce_conn_limit: bool,
    /// Drop a connection when its payload matches a panel detect rule (parity with
    /// the original SSR audit, which closed the connection on a match). When false
    /// matches are still reported to the panel but the connection is left open.
    #[serde(default = "default_true")]
    pub audit_block: bool,
    /// Enforce per-user `node_speedlimit` (Mbit/s) via a shared token bucket.
    /// Kill switch: set false to relay at full speed regardless of the panel cap.
    #[serde(default = "default_true")]
    pub enforce_speed: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "default_max_users")]
    pub max_users: usize,
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
    #[serde(default = "default_session_ttl_secs")]
    pub session_ttl_secs: u64,
    #[serde(default = "default_max_udp_associations")]
    pub max_udp_associations: usize,
    #[serde(default = "default_udp_association_ttl_secs")]
    pub udp_association_ttl_secs: u64,
    #[serde(default = "default_max_alive_ips")]
    pub max_alive_ips: usize,
    #[serde(default = "default_alive_ip_ttl_secs")]
    pub alive_ip_ttl_secs: u64,
    #[serde(default = "default_max_detect_logs")]
    pub max_detect_logs: usize,
    #[serde(default = "default_detect_log_ttl_secs")]
    pub detect_log_ttl_secs: u64,
    #[serde(default = "default_max_accepts_per_port")]
    pub max_accepts_per_port: usize,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let mut config: Self = toml::from_str(&raw).context("parsing config TOML")?;
        config.apply_env_overrides();
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.panel.base_url.trim().is_empty() {
            return Err(anyhow!("panel.base_url is required"));
        }
        if self.panel.key.trim().is_empty() {
            return Err(anyhow!("panel.key is required"));
        }
        if self.node.workers == 0 {
            return Err(anyhow!("node.workers must be >= 1"));
        }
        if self.node.server_port == 0 {
            return Err(anyhow!("node.server_port must be >= 1"));
        }
        if self.node.timeout_secs == 0 {
            return Err(anyhow!("node.timeout_secs must be >= 1"));
        }
        if self.limits.max_users == 0 || self.limits.max_sessions == 0 {
            return Err(anyhow!("limits.max_users and limits.max_sessions must be >= 1"));
        }
        crate::ssr::Profile::new(
            self.node.method.clone(),
            self.node.protocol.clone(),
            self.node.obfs.clone(),
            self.node.timeout(),
        )?;
        Ok(())
    }

    fn apply_env_overrides(&mut self) {
        if let Ok(value) = std::env::var("SSPANEL_PANEL_BASE_URL") {
            self.panel.base_url = value;
        }
        if let Ok(value) = std::env::var("SSPANEL_PANEL_KEY") {
            self.panel.key = value;
        }
        if let Ok(value) = std::env::var("SSPANEL_NODE_ID") {
            if let Ok(node_id) = value.parse() {
                self.panel.node_id = node_id;
            }
        }
    }
}

impl PanelConfig {
    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_secs)
    }

    pub fn poll_interval(&self) -> Duration {
        Duration::from_secs(self.poll_interval_secs)
    }

    pub fn traffic_report_interval(&self) -> Duration {
        Duration::from_secs(self.traffic_report_interval_secs)
    }

    pub fn heartbeat_interval(&self) -> Duration {
        Duration::from_secs(self.heartbeat_interval_secs)
    }
}

impl NodeConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }
}

impl LimitsConfig {
    pub fn session_ttl(&self) -> Duration {
        Duration::from_secs(self.session_ttl_secs)
    }

    pub fn udp_association_ttl(&self) -> Duration {
        Duration::from_secs(self.udp_association_ttl_secs)
    }

    pub fn alive_ip_ttl(&self) -> Duration {
        Duration::from_secs(self.alive_ip_ttl_secs)
    }

    pub fn detect_log_ttl(&self) -> Duration {
        Duration::from_secs(self.detect_log_ttl_secs)
    }
}

fn default_request_timeout_secs() -> u64 { 10 }
fn default_poll_interval_secs() -> u64 { 60 }
fn default_traffic_report_interval_secs() -> u64 { 60 }
fn default_heartbeat_interval_secs() -> u64 { 60 }
fn default_listen_host() -> String { "0.0.0.0".to_owned() }
fn default_method() -> String { "rc4-md5".to_owned() }
fn default_protocol() -> String { "auth_aes128_md5".to_owned() }
fn default_obfs() -> String { "plain".to_owned() }
fn default_server_port() -> u16 { 43003 }
fn default_timeout_secs() -> u64 { 300 }
fn default_workers() -> usize { 1 }
fn default_true() -> bool { true }
fn default_max_users() -> usize { 4096 }
fn default_max_sessions() -> usize { 65536 }
fn default_session_ttl_secs() -> u64 { 600 }
fn default_max_udp_associations() -> usize { 32768 }
fn default_udp_association_ttl_secs() -> u64 { 180 }
fn default_max_alive_ips() -> usize { 65536 }
fn default_alive_ip_ttl_secs() -> u64 { 600 }
fn default_max_detect_logs() -> usize { 8192 }
fn default_detect_log_ttl_secs() -> u64 { 3600 }
fn default_max_accepts_per_port() -> usize { 2048 }
