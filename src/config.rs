use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentConfig {
    #[serde(default)]
    pub data_dir: Option<String>,
    #[serde(default)]
    pub intervals: IntervalConfig,
    #[serde(default)]
    pub tunnel: TunnelConfig,
    pub mqtt: Option<MqttConfig>,
    #[serde(default = "default_api_url")]
    pub api_url: String,
    /// Base URL for TUF repo metadata fetches, e.g.
    /// `https://repos.staging.peridio.com/tuf/{device_id}/`
    /// Set during device provisioning.
    #[serde(default)]
    pub tuf_url: Option<String>,
    /// Base URL for artifact downloads, e.g.
    /// `https://repos.staging.peridio.com/artifacts/{org_id}/`
    /// Set during device provisioning.
    #[serde(default)]
    pub artifacts_url: Option<String>,
    /// Runtime identity reported in the device shadow on every MQTT connect.
    /// Populated from `/etc/avocado-release` or the `[runtime]` config section.
    #[serde(default)]
    pub runtime: Option<RuntimeConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    pub id: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
}

fn default_api_url() -> String {
    "http://localhost:3001".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MqttConfig {
    #[serde(default = "default_mqtt_host")]
    pub host: String,
    #[serde(default = "default_mqtt_port")]
    pub port: u16,
    pub username: String,
    pub password: String,
    pub client_id: String,
}

fn default_mqtt_host() -> String {
    "localhost".to_string()
}

fn default_mqtt_port() -> u16 {
    1883
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    #[serde(default = "default_rat_socket_path")]
    pub rat_socket_path: String,
    #[serde(default = "default_device_proxy_port")]
    pub device_proxy_port: u16,
    #[serde(default = "default_cidr_blocks")]
    pub cidr_blocks: Vec<String>,
    /// Optional lower bound for the WireGuard listen port range.
    /// Set both wg_port_lo and wg_port_hi to the same value to pin to a specific port.
    #[serde(default)]
    pub wg_port_lo: Option<u16>,
    /// Optional upper bound for the WireGuard listen port range.
    #[serde(default)]
    pub wg_port_hi: Option<u16>,
}

fn default_rat_socket_path() -> String {
    "/tmp/avocado-rat.sock".to_string()
}

fn default_device_proxy_port() -> u16 {
    22
}

fn default_cidr_blocks() -> Vec<String> {
    vec!["10.100.0.0/24".to_string()]
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            rat_socket_path: default_rat_socket_path(),
            device_proxy_port: default_device_proxy_port(),
            cidr_blocks: default_cidr_blocks(),
            wg_port_lo: None,
            wg_port_hi: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntervalConfig {
    /// MQTT keepalive interval in seconds. The broker fires LWT and marks the
    /// device offline if no traffic is received within this window.
    #[serde(default = "default_keepalive_secs", alias = "heartbeat_secs")]
    pub keepalive_secs: u64,
}

fn default_keepalive_secs() -> u64 {
    30
}

impl Default for IntervalConfig {
    fn default() -> Self {
        Self {
            keepalive_secs: default_keepalive_secs(),
        }
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            data_dir: None,
            intervals: IntervalConfig::default(),
            tunnel: TunnelConfig::default(),
            mqtt: None,
            api_url: default_api_url(),
            tuf_url: None,
            artifacts_url: None,
            runtime: None,
        }
    }
}

impl AgentConfig {
    pub fn default_path() -> Result<PathBuf> {
        if let Ok(p) = std::env::var("AVOCADO_DAEMON_CONFIG") {
            return Ok(PathBuf::from(p));
        }
        let dir = dirs::config_dir()
            .context("Could not determine config directory")?
            .join("avocado-daemon");
        Ok(dir.join("config.toml"))
    }

    pub fn load(path: &PathBuf) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = fs::read_to_string(path)?;
        let config: AgentConfig = toml::from_str(&data)?;
        Ok(config)
    }

    /// Resolve the MQTT config or fail with a clear error.
    pub fn resolve_mqtt(&self) -> Result<crate::config::MqttConfig> {
        self.mqtt.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "Missing [mqtt] section in config.toml.\n\
                 Add the credentials returned by the device claim API:\n\
                 [mqtt]\n\
                 host = \"<broker-host>\"\n\
                 port = 1883\n\
                 username = \"<device-uuid>\"\n\
                 password = \"<raw-mqtt-password>\"\n\
                 client_id = \"device-<device-uuid>\""
            )
        })
    }
}
