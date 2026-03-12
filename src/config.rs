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
    /// Varlink socket address for avocadoctl runtime management.
    /// Default: "unix:/run/avocado/avocadoctl.sock"
    #[serde(default = "default_avocadoctl_socket")]
    pub avocadoctl_socket: String,

    /// Claim token for initial device provisioning.
    /// If present and no saved credentials exist, the daemon will self-claim
    /// by calling POST {api_url}/api/device/claim.
    #[serde(default)]
    pub claim_token: Option<String>,
    /// Device ID provider name. Required when `claim_token` is set.
    /// Built-in: "dmi", "devicetree-serial", "rpi-serial", "imx-uid", "nic-mac"
    /// External: "file:<path>", "uboot-env:<var>", "exec:<path> [args...]"
    #[serde(default)]
    pub device_id_source: Option<String>,
    /// MQTT broker host for device connections (used after claiming).
    #[serde(default = "default_mqtt_host")]
    pub mqtt_host: String,
    /// MQTT broker port for device connections (used after claiming).
    #[serde(default = "default_mqtt_port")]
    pub mqtt_port: u16,
    /// Directory where TUF metadata (root.json) is stored.
    /// Must align with where avocadoctl expects to find root.json.
    #[serde(default = "default_metadata_dir")]
    pub metadata_dir: String,
}

/// Credentials and metadata persisted after a successful device claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimedState {
    pub device_id: String,
    pub mqtt: MqttConfig,
    pub tuf_url: Option<String>,
    pub artifacts_url: Option<String>,
    pub claimed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    pub id: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
}

fn default_api_url() -> String {
    "https://connect.peridio.com".to_string()
}

fn default_avocadoctl_socket() -> String {
    "unix:/run/avocado/avocadoctl.sock".to_string()
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

fn default_metadata_dir() -> String {
    "/var/lib/avocado/metadata".to_string()
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
            avocadoctl_socket: default_avocadoctl_socket(),
            claim_token: None,
            device_id_source: None,
            mqtt_host: default_mqtt_host(),
            mqtt_port: default_mqtt_port(),
            metadata_dir: default_metadata_dir(),
        }
    }
}

impl AgentConfig {
    pub fn default_path() -> Result<PathBuf> {
        if let Ok(p) = std::env::var("AVOCADO_CONN_CONFIG") {
            return Ok(PathBuf::from(p));
        }
        let dir = dirs::config_dir()
            .context("Could not determine config directory")?
            .join("avocado-conn");
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

    /// Resolve the MQTT config: check [mqtt] section first, then saved claim
    /// state, then error.
    pub fn resolve_mqtt(&self) -> Result<MqttConfig> {
        if let Some(mqtt) = &self.mqtt {
            return Ok(mqtt.clone());
        }
        if let Some(state) = self.load_claimed_state()? {
            return Ok(state.mqtt);
        }
        if self.claim_token.is_some() {
            anyhow::bail!(
                "Claim token present but device not yet claimed. \
                 The claim flow will run automatically."
            );
        }
        anyhow::bail!(
            "Missing [mqtt] section in config.toml.\n\
             Add the credentials returned by the device claim API:\n\
             [mqtt]\n\
             host = \"<broker-host>\"\n\
             port = 1883\n\
             username = \"<device-uuid>\"\n\
             password = \"<raw-mqtt-password>\"\n\
             client_id = \"device-<device-uuid>\""
        )
    }

    /// Validate that required fields are present when claim_token is set.
    pub fn validate_claim_config(&self) -> Result<()> {
        if self.claim_token.is_some() {
            if self.data_dir.is_none() {
                anyhow::bail!(
                    "data_dir must be set when using claim_token. \
                     Set data_dir to a persistent writable directory, \
                     e.g. data_dir = \"/var/lib/avocado/connect\""
                );
            }
            if self.device_id_source.is_none() {
                anyhow::bail!(
                    "device_id_source must be set when using claim_token.\n\
                     Built-in providers: \"dmi\", \"devicetree-serial\", \
                     \"rpi-serial\", \"imx-uid\", \"nic-mac\"\n\
                     External: \"file:<path>\", \"uboot-env:<var>\", \
                     \"exec:<path> [args...]\""
                );
            }
        }
        Ok(())
    }

    /// Path to the saved claim state file inside data_dir.
    pub fn state_file_path(&self) -> Option<PathBuf> {
        self.data_dir
            .as_ref()
            .map(|d| PathBuf::from(d).join("claimed_state.json"))
    }

    /// Load previously saved claim credentials from disk.
    pub fn load_claimed_state(&self) -> Result<Option<ClaimedState>> {
        match self.state_file_path() {
            Some(path) if path.exists() => {
                let data = fs::read_to_string(&path)
                    .with_context(|| format!("reading {}", path.display()))?;
                let state: ClaimedState = serde_json::from_str(&data)
                    .with_context(|| format!("parsing {}", path.display()))?;
                Ok(Some(state))
            }
            _ => Ok(None),
        }
    }

    /// Atomically persist claim credentials to disk.
    pub fn save_claimed_state(&self, state: &ClaimedState) -> Result<()> {
        let path = self
            .state_file_path()
            .ok_or_else(|| anyhow::anyhow!("data_dir must be set to save claim state"))?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        let tmp = path.with_extension("tmp");
        let data = serde_json::to_string_pretty(state)?;
        fs::write(&tmp, &data).with_context(|| format!("writing {}", tmp.display()))?;
        fs::rename(&tmp, &path)
            .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Check if the device has already been claimed (state file exists).
    pub fn is_claimed(&self) -> bool {
        self.state_file_path().map(|p| p.exists()).unwrap_or(false)
    }

    /// Check if claim-based provisioning is configured.
    pub fn needs_claim(&self) -> bool {
        self.claim_token.is_some() && !self.is_claimed()
    }
}
