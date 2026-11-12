use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

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
    /// Read the claim token from this file instead of `claim_token`, e.g. a
    /// file placed on /var at provision so the token stays out of the image.
    /// Not needed once the device is claimed.
    #[serde(default)]
    pub claim_token_file: Option<String>,
    /// Delete `claim_token_file` once the claim credentials are saved.
    /// Default false. A device whose saved credentials are later lost then
    /// cannot claim again until a new token is provided.
    #[serde(default)]
    pub remove_claim_token_file: bool,
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
    /// Optional local handler process (see `local_handler`). Unset: off.
    #[serde(default)]
    pub local_handler: Option<LocalHandlerConfig>,
}

/// `[local_handler]`: Unix socket of a local process that receives server
/// messages conn doesn't handle itself and whose lines are published as events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalHandlerConfig {
    pub socket: String,
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
    /// Explicit TLS toggle from the claim API. When `None`, auto-detect by port
    /// (8883 → TLS, else plain TCP).
    #[serde(default)]
    pub tls: Option<bool>,
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
    /// Seconds to wait for `rat` to answer a request. Requests run inline in
    /// the MQTT loop, so a hung `rat` would otherwise stop command handling.
    #[serde(default = "default_rat_timeout_secs")]
    pub rat_timeout_secs: u64,
}

fn default_rat_timeout_secs() -> u64 {
    30
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
            rat_timeout_secs: default_rat_timeout_secs(),
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
            claim_token_file: None,
            remove_claim_token_file: false,
            device_id_source: None,
            mqtt_host: default_mqtt_host(),
            mqtt_port: default_mqtt_port(),
            metadata_dir: default_metadata_dir(),
            local_handler: None,
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
        let mut config: AgentConfig = toml::from_str(&data)?;
        config.read_claim_token_file()?;
        Ok(config)
    }

    /// Fill `claim_token` from `claim_token_file`. A missing file leaves it
    /// unset: fine once claimed (it may have been removed after the claim),
    /// and reported by `missing_claim_token_file` otherwise.
    fn read_claim_token_file(&mut self) -> Result<()> {
        let Some(path) = &self.claim_token_file else {
            return Ok(());
        };
        if self.claim_token.is_some() {
            anyhow::bail!("set claim_token or claim_token_file, not both");
        }
        match fs::read_to_string(path) {
            Ok(s) if s.trim().is_empty() => anyhow::bail!("claim_token_file {path} is empty"),
            Ok(s) => self.claim_token = Some(s.trim().to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e).with_context(|| format!("reading claim_token_file {path}"));
            }
        }
        Ok(())
    }

    /// The configured token file when an unclaimed device has none to read.
    pub fn missing_claim_token_file(&self) -> Option<&str> {
        match &self.claim_token_file {
            Some(path) if self.claim_token.is_none() && !self.is_claimed() => Some(path),
            _ => None,
        }
    }

    /// With `remove_claim_token_file`, delete the token file of a claimed
    /// device. Runs on every start, so a crash between saving the claim and
    /// removing the file is cleaned up next time.
    pub fn remove_claim_token_file_if_claimed(&self) {
        let Some(path) = &self.claim_token_file else {
            return;
        };
        if !self.remove_claim_token_file || !self.is_claimed() {
            return;
        }
        match fs::remove_file(path) {
            Ok(()) => tracing::info!(path = %path, "removed claim token file"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(path = %path, error = %e, "could not remove claim token file"),
        }
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
        // Durable before visible: a power cut right after the claim must not
        // leave an empty state file (the claim token is single-use, so the
        // device could never recover on its own). fsync the data, rename,
        // then fsync the directory so the rename itself is on disk.
        // A .tmp left by an earlier crash may have a wider mode; `mode()` only
        // applies on create, so start from a fresh file.
        let _ = fs::remove_file(&tmp);
        {
            use std::io::Write;
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts
                .open(&tmp)
                .with_context(|| format!("writing {}", tmp.display()))?;
            f.write_all(data.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &path)
            .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
        // Make the rename durable, and data_dir's own entry too: it may have
        // been created moments ago (service mkdir or create_dir_all above).
        if let Some(parent) = path.parent() {
            sync_dir(parent)?;
            if let Some(grandparent) = parent.parent() {
                sync_dir(grandparent)?;
            }
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

/// fsync a directory. A relative path's last parent is "", which means the
/// current directory.
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    fs::File::open(dir)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relative_data_dir_syncs_the_current_directory() {
        // data_dir = "state" gives a grandparent of "".
        let parent = Path::new("state/claimed_state.json").parent().unwrap();
        assert_eq!(parent.parent(), Some(Path::new("")));
        sync_dir(parent.parent().unwrap()).unwrap();
    }

    #[test]
    fn a_claim_token_file_is_read_and_removed_after_the_claim() {
        let dir = std::env::temp_dir().join(format!("conn-token-file-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let token = dir.join("claim_token");
        let conf = dir.join("config.toml");
        let write_conf = |extra: &str| {
            fs::write(
                &conf,
                format!(
                    "data_dir = {:?}\nclaim_token_file = {:?}\n{extra}",
                    dir.join("state"),
                    token
                ),
            )
            .unwrap()
        };

        // Unclaimed and no file: reported, so the daemon idles instead of
        // exiting into a systemd restart loop.
        write_conf("remove_claim_token_file = true");
        let cfg = AgentConfig::load(&conf).unwrap();
        assert_eq!(
            cfg.missing_claim_token_file(),
            Some(token.to_str().unwrap())
        );

        fs::write(&token, "tok-123\n").unwrap();
        let cfg = AgentConfig::load(&conf).unwrap();
        assert_eq!(cfg.claim_token.as_deref(), Some("tok-123"));
        assert!(cfg.needs_claim());

        // Not claimed yet: the file stays.
        cfg.remove_claim_token_file_if_claimed();
        assert!(token.exists());

        let state: ClaimedState = serde_json::from_str(
            r#"{"device_id":"d1","mqtt":{"username":"u","password":"p","client_id":"c"},
                "tuf_url":null,"artifacts_url":null,"claimed_at":"now"}"#,
        )
        .unwrap();
        cfg.save_claimed_state(&state).unwrap();
        cfg.remove_claim_token_file_if_claimed();
        assert!(!token.exists());

        // Restart after removal: claimed, no token needed.
        let cfg = AgentConfig::load(&conf).unwrap();
        assert!(cfg.claim_token.is_none() && !cfg.needs_claim());
        assert_eq!(cfg.missing_claim_token_file(), None);

        // Without the option the file is kept.
        fs::write(&token, "tok-123").unwrap();
        write_conf("");
        AgentConfig::load(&conf)
            .unwrap()
            .remove_claim_token_file_if_claimed();
        assert!(token.exists());

        // Both ways of giving the token is a config error.
        write_conf("claim_token = \"inline\"");
        assert!(AgentConfig::load(&conf).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rat_timeout_defaults_to_30s_and_is_configurable() {
        let cfg: AgentConfig = toml::from_str("").unwrap();
        assert_eq!(cfg.tunnel.rat_timeout_secs, 30);
        let cfg: AgentConfig = toml::from_str("[tunnel]\nrat_timeout_secs = 5").unwrap();
        assert_eq!(cfg.tunnel.rat_timeout_secs, 5);
    }

    #[test]
    fn claimed_state_survives_a_restart() {
        let dir = std::env::temp_dir().join(format!("conn-claim-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let cfg = AgentConfig {
            data_dir: Some(dir.join("state").to_string_lossy().into()),
            claim_token: Some("single-use".into()),
            ..Default::default()
        };
        let state: ClaimedState = serde_json::from_str(
            r#"{"device_id":"d1","mqtt":{"username":"u","password":"p","client_id":"c"},
                "tuf_url":null,"artifacts_url":null,"claimed_at":"now"}"#,
        )
        .unwrap();
        // A stale, world-readable .tmp from an earlier crash must not leak
        // the credentials.
        let tmp = cfg.state_file_path().unwrap().with_extension("tmp");
        fs::create_dir_all(tmp.parent().unwrap()).unwrap();
        fs::write(&tmp, "stale").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644)).unwrap();
        }
        cfg.save_claimed_state(&state).unwrap();

        // A fresh config (as after a restart) sees the claim and won't re-claim.
        let restarted = AgentConfig {
            data_dir: cfg.data_dir.clone(),
            claim_token: cfg.claim_token.clone(),
            ..Default::default()
        };
        assert!(!restarted.needs_claim());
        let loaded = restarted.load_claimed_state().unwrap().unwrap();
        assert_eq!(loaded.device_id, "d1");
        assert_eq!(loaded.mqtt.password, "p");
        let path = restarted.state_file_path().unwrap();
        assert!(!path.with_extension("tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
