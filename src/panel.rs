use std::net::{IpAddr, Ipv4Addr};

use anyhow::{anyhow, Context, Result};
use reqwest::Url;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{config::PanelConfig, traffic::TrafficDelta};

#[derive(Debug, Clone, Deserialize)]
pub struct PanelUser {
    pub id: u64,
    #[serde(default)]
    pub user_id: Option<u64>,
    pub port: u16,
    #[serde(default, alias = "passwd")]
    pub password: String,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default, alias = "protocol_param")]
    #[allow(dead_code)]
    pub protocol_param: Option<String>,
    #[serde(default)]
    pub obfs: Option<String>,
    #[serde(default, alias = "obfs_param")]
    #[allow(dead_code)]
    pub obfs_param: Option<String>,
    #[serde(default)]
    pub enable: Option<i64>,
    #[serde(default)]
    pub is_multi_user: i64,
    /// Per-user rate cap in Mbit/s (0 = unlimited).
    #[serde(default)]
    pub node_speedlimit: Option<f64>,
    /// Max concurrent connections for this user (0 = unlimited).
    #[serde(default)]
    pub node_connector: Option<i64>,
    /// Comma-separated IP/CIDR list the user may not reach.
    #[serde(default)]
    pub forbidden_ip: Option<String>,
    /// Comma-separated port / port-range list the user may not reach.
    #[serde(default)]
    pub forbidden_port: Option<String>,
}

impl PanelUser {
    pub fn user_id(&self) -> u64 {
        self.user_id.unwrap_or(self.id)
    }

    pub fn is_enabled(&self) -> bool {
        self.enable.unwrap_or(1) != 0
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct NodeInfo {
    /// Panel returns the node's address in `server`. For sort 0/10 this is a
    /// ';'-separated string whose first field is the IPv4 address.
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub sort: Option<i64>,
    #[serde(default)]
    pub traffic_rate: Option<f64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DetectRule {
    pub id: u64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub regex: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RelayRule {
    pub id: u64,
    #[serde(default)]
    pub source_node_id: Option<u64>,
    #[serde(default)]
    pub dist_node_id: Option<u64>,
    #[serde(default)]
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AliveIpReport {
    pub user_id: u64,
    pub ip: String,
}

/// Panel's addDetectLog only reads `list_id` + `user_id`; it does not store the
/// offending IP. We keep the IP in the local dedup key (DetectLogKey), not here.
#[derive(Debug, Clone, Serialize)]
pub struct DetectLogReport {
    pub user_id: u64,
    pub list_id: u64,
}

#[derive(Debug, Deserialize)]
struct ApiResponse<T> {
    ret: i64,
    #[serde(default)]
    msg: Option<String>,
    #[serde(default)]
    data: Option<T>,
}

#[derive(Clone)]
pub struct PanelClient {
    base: Url,
    key: String,
    node_id: u64,
    http: reqwest::Client,
}

impl PanelClient {
    pub fn new(config: &PanelConfig) -> Result<Self> {
        let mut base = Url::parse(config.base_url.trim_end_matches('/'))
            .context("panel.base_url is not a valid URL")?;
        base.set_path("");
        let mut builder = reqwest::Client::builder()
            .timeout(config.request_timeout())
            .user_agent("sspanel-ssr-rust-backend/0.1");
        if config.ipv4_only {
            // Bind the local socket to an IPv4 address so all webapi requests
            // egress over IPv4. This keeps the panel's checkNodeIp happy on
            // IPv6-capable hosts (otherwise: "IP is invalid").
            builder = builder.local_address(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        }
        let http = builder.build().context("building HTTP client")?;
        Ok(Self {
            base,
            key: config.key.clone(),
            node_id: config.node_id,
            http,
        })
    }

    pub async fn ping(&self) -> Result<()> {
        let value: Value = self.get_json("func/ping", &[]).await?;
        unwrap_ret::<Value>("func/ping", value).map(|_| ())
    }

    pub async fn node_info(&self) -> Result<Option<NodeInfo>> {
        let path = format!("nodes/{}/info", self.node_id);
        self.get_api_optional(&path, &[]).await
    }

    pub async fn report_node_info(&self, load: &str, uptime: u64) -> Result<()> {
        let path = format!("nodes/{}/info", self.node_id);
        let body = json!({ "load": load, "uptime": uptime });
        self.post_ack(&path, &[], body).await
    }

    pub async fn users(&self) -> Result<Vec<PanelUser>> {
        let node_id = self.node_id.to_string();
        let users: Option<Vec<PanelUser>> = self
            .get_api_optional("users", &[("node_id", node_id.as_str())])
            .await?;
        Ok(users
            .unwrap_or_default()
            .into_iter()
            .filter(PanelUser::is_enabled)
            .collect())
    }

    pub async fn report_traffic(&self, deltas: &[TrafficDelta]) -> Result<()> {
        if deltas.is_empty() {
            return Ok(());
        }
        let node_id = self.node_id.to_string();
        let data: Vec<Value> = deltas
            .iter()
            .map(|delta| {
                json!({
                    "user_id": delta.user_id,
                    "u": delta.upload,
                    "d": delta.download,
                })
            })
            .collect();
        self.post_ack(
            "users/traffic",
            &[("node_id", node_id.as_str())],
            json!({ "data": data }),
        )
        .await
    }

    pub async fn report_alive_ips(&self, items: &[AliveIpReport]) -> Result<()> {
        if items.is_empty() {
            return Ok(());
        }
        let node_id = self.node_id.to_string();
        self.post_ack(
            "users/aliveip",
            &[("node_id", node_id.as_str())],
            json!({ "data": items }),
        )
        .await
    }

    pub async fn report_detect_logs(&self, items: &[DetectLogReport]) -> Result<()> {
        if items.is_empty() {
            return Ok(());
        }
        let node_id = self.node_id.to_string();
        self.post_ack(
            "users/detectlog",
            &[("node_id", node_id.as_str())],
            json!({ "data": items }),
        )
        .await
    }

    pub async fn detect_rules(&self) -> Result<Vec<DetectRule>> {
        Ok(self.get_api_optional("func/detect_rules", &[]).await?.unwrap_or_default())
    }

    pub async fn relay_rules(&self) -> Result<Vec<RelayRule>> {
        let node_id = self.node_id.to_string();
        Ok(self
            .get_api_optional("func/relay_rules", &[("node_id", node_id.as_str())])
            .await?
            .unwrap_or_default())
    }

    async fn get_api_optional<T>(&self, path: &str, query: &[(&str, &str)]) -> Result<Option<T>>
    where
        T: DeserializeOwned,
    {
        let value = self.get_json(path, query).await?;
        unwrap_ret(path, value)
    }

    async fn post_ack(&self, path: &str, query: &[(&str, &str)], body: Value) -> Result<()> {
        let url = self.url(path, query)?;
        let value = self
            .http
            .post(url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST /mod_mu/{path}"))?
            .error_for_status()
            .with_context(|| format!("POST /mod_mu/{path} status"))?
            .json::<Value>()
            .await
            .with_context(|| format!("decoding /mod_mu/{path} response"))?;
        unwrap_ret::<Value>(path, value).map(|_| ())
    }

    async fn get_json(&self, path: &str, query: &[(&str, &str)]) -> Result<Value> {
        let url = self.url(path, query)?;
        self.http
            .get(url)
            .send()
            .await
            .with_context(|| format!("GET /mod_mu/{path}"))?
            .error_for_status()
            .with_context(|| format!("GET /mod_mu/{path} status"))?
            .json::<Value>()
            .await
            .with_context(|| format!("decoding /mod_mu/{path} response"))
    }

    fn url(&self, path: &str, query: &[(&str, &str)]) -> Result<Url> {
        let mut url = self.base.join(&format!("/mod_mu/{path}"))?;
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("key", &self.key);
            for (key, value) in query {
                pairs.append_pair(key, value);
            }
        }
        Ok(url)
    }
}

fn unwrap_ret<T>(path: &str, value: Value) -> Result<Option<T>>
where
    T: DeserializeOwned,
{
    let response: ApiResponse<Value> =
        serde_json::from_value(value).with_context(|| format!("parsing /mod_mu/{path} envelope"))?;
    if response.ret != 1 {
        return Err(anyhow!(
            "/mod_mu/{path} returned ret={} msg={}",
            response.ret,
            response.msg.unwrap_or_default()
        ));
    }
    match response.data {
        Some(value) if !value.is_null() => {
            let parsed = serde_json::from_value(value)
                .with_context(|| format!("parsing /mod_mu/{path} data"))?;
            Ok(Some(parsed))
        }
        _ => Ok(None),
    }
}
