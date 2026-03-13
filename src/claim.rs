use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::config::{AgentConfig, ClaimedState, MqttConfig};
use crate::device_id;

// ---------------------------------------------------------------------------
// API request/response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ClaimRequest {
    token: String,
    hardware_fingerprint: String,
}

#[derive(Deserialize)]
struct ClaimResponse {
    data: ClaimData,
}

#[derive(Deserialize)]
struct ClaimData {
    device: ClaimDevice,
    #[allow(dead_code)]
    api_token: String,
    mqtt: ClaimMqtt,
    tuf_url: Option<String>,
    artifacts_url: Option<String>,
    /// Signed root.json envelope for trust initialization (Level 0 TOFU).
    /// Present when the org has TUF configured on the server.
    root_json: Option<String>,
}

#[derive(Deserialize)]
struct ClaimDevice {
    id: String,
    #[allow(dead_code)]
    name: String,
}

#[derive(Deserialize)]
struct ClaimMqtt {
    host: String,
    port: u16,
    username: String,
    password: String,
    client_id: String,
    /// Server-provided TLS hint. When absent, the daemon auto-detects by port.
    tls: Option<bool>,
}

#[derive(Deserialize)]
struct ClaimErrorBody {
    error: String,
    #[allow(dead_code)]
    message: String,
}

// ---------------------------------------------------------------------------
// Claim errors
// ---------------------------------------------------------------------------

/// Error codes returned by the claim API that are not worth retrying.
const PERMANENT_ERRORS: &[&str] = &["invalid_token", "expired_token", "exhausted_token"];

/// Check if an error message contains a permanent (non-retriable) error code.
fn is_permanent_error(msg: &str) -> bool {
    PERMANENT_ERRORS.iter().any(|code| msg.contains(code))
}

// ---------------------------------------------------------------------------
// Single claim attempt
// ---------------------------------------------------------------------------

/// Write root.json from the claim response to the metadata directory.
/// Creates `root.json` and `1.root.json` (TUF versioned copy).
fn write_root_json(metadata_dir: &str, root_json: &str) -> Result<()> {
    let dir = std::path::Path::new(metadata_dir);
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating metadata dir {}", dir.display()))?;

    let root_path = dir.join("root.json");
    let versioned_path = dir.join("1.root.json");

    std::fs::write(&root_path, root_json)
        .with_context(|| format!("writing {}", root_path.display()))?;
    std::fs::write(&versioned_path, root_json)
        .with_context(|| format!("writing {}", versioned_path.display()))?;

    info!(path = %root_path.display(), "wrote root.json from claim response");
    Ok(())
}

/// Execute a single claim attempt against the API.
pub async fn claim(config: &AgentConfig) -> Result<ClaimedState> {
    let token = config
        .claim_token
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no claim_token in config"))?
        .clone();

    let source = config
        .device_id_source
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("no device_id_source in config"))?
        .to_string();

    let api_url = config.api_url.clone();
    let metadata_dir = config.metadata_dir.clone();

    // Run the blocking HTTP call on a separate thread so we don't block the
    // tokio current_thread runtime.
    tokio::task::spawn_blocking(move || {
        let fingerprint = device_id::resolve_device_id(&source)?;

        let url = format!("{}/api/device/claim", api_url);
        info!(url = %url, fingerprint = %fingerprint, "attempting device claim");

        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .build();
        let agent = ureq::Agent::new_with_config(config);

        let mut resp = agent
            .post(&url)
            .send_json(&ClaimRequest {
                token,
                hardware_fingerprint: fingerprint,
            })
            .map_err(|e| anyhow::anyhow!("claim request failed: {e}"))?;

        let status = resp.status();
        if status.is_success() {
            let claim_resp: ClaimResponse = resp
                .body_mut()
                .read_json()
                .map_err(|e| anyhow::anyhow!("parsing claim response: {e}"))?;

            // Write root.json to metadata dir if provided (Level 0 TOFU)
            if let Some(ref root_json) = claim_resp.data.root_json
                && let Err(e) = write_root_json(&metadata_dir, root_json)
            {
                warn!(error = %e, "failed to write root.json from claim response");
            }

            let state = ClaimedState {
                device_id: claim_resp.data.device.id,
                mqtt: MqttConfig {
                    host: claim_resp.data.mqtt.host,
                    port: claim_resp.data.mqtt.port,
                    username: claim_resp.data.mqtt.username,
                    password: claim_resp.data.mqtt.password,
                    client_id: claim_resp.data.mqtt.client_id,
                    tls: claim_resp.data.mqtt.tls,
                },
                tuf_url: claim_resp.data.tuf_url,
                artifacts_url: claim_resp.data.artifacts_url,
                claimed_at: chrono::Utc::now().to_rfc3339(),
            };
            Ok(state)
        } else {
            let err_body: ClaimErrorBody = resp.body_mut().read_json().unwrap_or(ClaimErrorBody {
                error: format!("http_{}", status),
                message: "unknown error".to_string(),
            });
            bail!(
                "claim failed ({}): {} — {}",
                status,
                err_body.error,
                err_body.message
            )
        }
    })
    .await?
}

// ---------------------------------------------------------------------------
// Retry loop
// ---------------------------------------------------------------------------

/// Claim with exponential backoff. Returns on success or permanent failure.
///
/// Backoff: 5s, 10s, 20s, 40s, ... capped at 300s.
/// Permanent failures (invalid/expired/exhausted token) abort immediately.
/// Network errors and retriable API errors (identifier_taken, reclaim_pending)
/// are retried indefinitely.
pub async fn claim_with_retry(config: &AgentConfig) -> Result<ClaimedState> {
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        match claim(config).await {
            Ok(state) => return Ok(state),
            Err(e) => {
                let msg = e.to_string();
                let delay_secs = std::cmp::min(
                    5u64.saturating_mul(2u64.pow(attempt.saturating_sub(1))),
                    300,
                );

                if is_permanent_error(&msg) {
                    error!(attempt, error = %msg, "claim failed permanently");
                    return Err(e);
                }

                warn!(
                    attempt,
                    delay_secs,
                    error = %msg,
                    "claim failed, retrying..."
                );
                tokio::time::sleep(Duration::from_secs(delay_secs)).await;
            }
        }
    }
}
