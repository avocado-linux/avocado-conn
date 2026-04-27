use std::time::Duration;

use anyhow::{Context, Result};
use rand::Rng;
use reqwest::StatusCode;
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

#[derive(Deserialize, Default)]
struct ClaimErrorBody {
    #[serde(default)]
    error: String,
    #[serde(default)]
    message: String,
}

// ---------------------------------------------------------------------------
// Claim errors
// ---------------------------------------------------------------------------

/// Non-retriable claim failure.
///
/// The request will never succeed as-is. The daemon must stop retrying and
/// wait for operator intervention (fix config, clear conflicting device
/// record, issue new token, etc.). A process restart re-enters the claim
/// flow and attempts once more.
#[derive(Debug, Clone)]
pub struct PermanentClaimError {
    pub status: Option<u16>,
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for PermanentClaimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.status {
            Some(s) => write!(
                f,
                "claim rejected (HTTP {s}, {}): {}",
                self.code, self.message
            ),
            None => write!(f, "claim rejected ({}): {}", self.code, self.message),
        }
    }
}

impl std::error::Error for PermanentClaimError {}

/// Result of a single claim attempt — classified by caller action.
#[derive(Debug)]
enum AttemptError {
    /// Stop immediately. See `PermanentClaimError`.
    Permanent(PermanentClaimError),
    /// Back off and retry. `retry_after` honors the server's `Retry-After`
    /// header when present; callers fall back to jittered exponential backoff.
    Transient {
        code: String,
        message: String,
        retry_after: Option<Duration>,
    },
}

// ---------------------------------------------------------------------------
// Retry tuning
// ---------------------------------------------------------------------------

const INITIAL_BACKOFF: Duration = Duration::from_secs(5);
const MAX_BACKOFF: Duration = Duration::from_secs(300);
/// Upper bound for server-supplied `Retry-After` values. Protects against
/// runaway server configuration pinning a device offline.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(3600);
/// Multiplicative jitter band applied to computed backoff (±20%).
const JITTER_RATIO: f64 = 0.20;

/// Parse RFC 9110 §10.2.3 `Retry-After` as delta-seconds.
///
/// We intentionally ignore the HTTP-date form — device clocks may be unsynced
/// and seconds is the common form for rate limiters. Zero or non-numeric values
/// return `None` so callers fall back to local backoff (honoring `0` would
/// cause a tight retry loop). Values exceeding `MAX_RETRY_AFTER` are clamped.
fn parse_retry_after(value: &reqwest::header::HeaderValue) -> Option<Duration> {
    let s = value.to_str().ok()?.trim();
    let secs: u64 = s.parse().ok()?;
    if secs == 0 {
        return None;
    }
    Some(Duration::from_secs(secs).min(MAX_RETRY_AFTER))
}

/// Exponential backoff with ±20% jitter. The exponential target is capped at
/// `MAX_BACKOFF` *before* jitter is applied, so the realized delay can exceed
/// `MAX_BACKOFF` by up to `JITTER_RATIO`.
fn jittered_backoff(attempt: u32) -> Duration {
    let base = INITIAL_BACKOFF.as_secs_f64();
    let cap = MAX_BACKOFF.as_secs_f64();
    let exp = base * 2f64.powi(attempt.saturating_sub(1).min(16) as i32);
    let target = exp.min(cap);
    let jitter = rand::thread_rng().gen_range((1.0 - JITTER_RATIO)..=(1.0 + JITTER_RATIO));
    Duration::from_secs_f64((target * jitter).max(base))
}

/// Classify an HTTP response that was not 2xx.
///
/// - `429 Too Many Requests` → Transient (honors `Retry-After`)
/// - `5xx` / 3xx / 1xx → Transient
/// - Any other 4xx → Permanent. A well-formed request that returns 400/401/
///   403/404/409/422 will keep returning the same error on retry. This
///   prevents the 409 `identifier_taken` retry storm (ENG-1822) and every
///   analogous case for future 4xx codes.
fn classify(
    status: StatusCode,
    code: String,
    message: String,
    retry_after: Option<Duration>,
) -> AttemptError {
    if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        return AttemptError::Transient {
            code,
            message,
            retry_after,
        };
    }
    if status.is_client_error() {
        return AttemptError::Permanent(PermanentClaimError {
            status: Some(status.as_u16()),
            code,
            message,
        });
    }
    AttemptError::Transient {
        code,
        message,
        retry_after,
    }
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

fn permanent(code: &str, message: impl Into<String>) -> AttemptError {
    AttemptError::Permanent(PermanentClaimError {
        status: None,
        code: code.into(),
        message: message.into(),
    })
}

fn transient(code: &str, message: impl Into<String>) -> AttemptError {
    AttemptError::Transient {
        code: code.into(),
        message: message.into(),
        retry_after: None,
    }
}

/// Execute a single claim attempt against the API.
async fn claim_once(config: &AgentConfig) -> Result<ClaimedState, AttemptError> {
    let token = config
        .claim_token
        .as_deref()
        .ok_or_else(|| permanent("missing_claim_token", "no claim_token in config"))?;

    let source = config
        .device_id_source
        .as_deref()
        .ok_or_else(|| permanent("missing_device_id_source", "no device_id_source in config"))?;

    let fingerprint = device_id::resolve_device_id(source)
        .map_err(|e| permanent("device_id_resolution_failed", e.to_string()))?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| transient("client_build_failed", e.to_string()))?;

    let url = format!("{}/api/device/claim", config.api_url);
    info!(url = %url, fingerprint = %fingerprint, "attempting device claim");

    let resp = client
        .post(&url)
        .json(&ClaimRequest {
            token: token.to_string(),
            hardware_fingerprint: fingerprint,
        })
        .send()
        .await
        .map_err(|e| transient("network_error", e.to_string()))?;

    let status = resp.status();
    let retry_after = resp
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(parse_retry_after);

    if status.is_success() {
        let body: ClaimResponse = resp
            .json()
            .await
            .map_err(|e| transient("parse_error", format!("parsing claim response: {e}")))?;

        if let Some(ref root_json) = body.data.root_json
            && let Err(e) = write_root_json(&config.metadata_dir, root_json)
        {
            warn!(error = %e, "failed to write root.json from claim response");
        }

        return Ok(ClaimedState {
            device_id: body.data.device.id,
            mqtt: MqttConfig {
                host: body.data.mqtt.host,
                port: body.data.mqtt.port,
                username: body.data.mqtt.username,
                password: body.data.mqtt.password,
                client_id: body.data.mqtt.client_id,
                tls: body.data.mqtt.tls,
            },
            tuf_url: body.data.tuf_url,
            artifacts_url: body.data.artifacts_url,
            claimed_at: chrono::Utc::now().to_rfc3339(),
        });
    }

    let err_body = resp.json::<ClaimErrorBody>().await.unwrap_or_default();
    let code = if err_body.error.is_empty() {
        format!("http_{}", status.as_u16())
    } else {
        err_body.error
    };
    let message = if err_body.message.is_empty() {
        format!("HTTP {status}")
    } else {
        err_body.message
    };

    Err(classify(status, code, message, retry_after))
}

// ---------------------------------------------------------------------------
// Retry loop
// ---------------------------------------------------------------------------

/// Claim with jittered exponential backoff.
///
/// - Success → returns the claimed state.
/// - Permanent (409 identifier_taken, invalid/expired token, malformed
///   request, etc.) → returns `PermanentClaimError` immediately. Callers
///   should idle rather than crash-loop — a process restart retries once.
/// - Transient (5xx, 429, network) → retries indefinitely. Honors
///   `Retry-After` when present on transient HTTP responses (e.g., 429 or
///   503); falls back to jittered backoff otherwise (5s → 300s, ±20%).
pub async fn claim_with_retry(config: &AgentConfig) -> Result<ClaimedState, PermanentClaimError> {
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        match claim_once(config).await {
            Ok(state) => return Ok(state),
            Err(AttemptError::Permanent(e)) => {
                error!(
                    attempt,
                    status = ?e.status,
                    code = %e.code,
                    message = %e.message,
                    "claim failed permanently"
                );
                return Err(e);
            }
            Err(AttemptError::Transient {
                code,
                message,
                retry_after,
            }) => {
                let delay = retry_after.unwrap_or_else(|| jittered_backoff(attempt));
                warn!(
                    attempt,
                    delay_secs = delay.as_secs(),
                    code = %code,
                    server_retry_after = retry_after.is_some(),
                    error = %message,
                    "claim failed, retrying"
                );
                tokio::time::sleep(delay).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderValue;

    fn classify_status(status: u16) -> AttemptError {
        classify(
            StatusCode::from_u16(status).unwrap(),
            "err".into(),
            "msg".into(),
            None,
        )
    }

    #[test]
    fn classify_409_is_permanent() {
        assert!(matches!(classify_status(409), AttemptError::Permanent(_)));
    }

    #[test]
    fn classify_400_is_permanent() {
        assert!(matches!(classify_status(400), AttemptError::Permanent(_)));
    }

    #[test]
    fn classify_401_is_permanent() {
        assert!(matches!(classify_status(401), AttemptError::Permanent(_)));
    }

    #[test]
    fn classify_404_is_permanent() {
        assert!(matches!(classify_status(404), AttemptError::Permanent(_)));
    }

    #[test]
    fn classify_422_is_permanent() {
        assert!(matches!(classify_status(422), AttemptError::Permanent(_)));
    }

    #[test]
    fn classify_429_is_transient() {
        assert!(matches!(
            classify_status(429),
            AttemptError::Transient { .. }
        ));
    }

    #[test]
    fn classify_500_is_transient() {
        assert!(matches!(
            classify_status(500),
            AttemptError::Transient { .. }
        ));
    }

    #[test]
    fn classify_503_is_transient() {
        assert!(matches!(
            classify_status(503),
            AttemptError::Transient { .. }
        ));
    }

    #[test]
    fn classify_429_propagates_retry_after() {
        let err = classify(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited".into(),
            "msg".into(),
            Some(Duration::from_secs(42)),
        );
        match err {
            AttemptError::Transient { retry_after, .. } => {
                assert_eq!(retry_after, Some(Duration::from_secs(42)));
            }
            _ => panic!("expected Transient"),
        }
    }

    #[test]
    fn parse_retry_after_seconds() {
        let v = HeaderValue::from_static("60");
        assert_eq!(parse_retry_after(&v), Some(Duration::from_secs(60)));
    }

    #[test]
    fn parse_retry_after_whitespace() {
        let v = HeaderValue::from_static(" 10 ");
        assert_eq!(parse_retry_after(&v), Some(Duration::from_secs(10)));
    }

    #[test]
    fn parse_retry_after_zero() {
        let v = HeaderValue::from_static("0");
        assert_eq!(parse_retry_after(&v), None);
    }

    #[test]
    fn parse_retry_after_non_numeric_rejected() {
        // We intentionally don't parse HTTP-date form — device clocks may drift.
        let v = HeaderValue::from_static("Wed, 21 Oct 2026 07:28:00 GMT");
        assert_eq!(parse_retry_after(&v), None);
    }

    #[test]
    fn parse_retry_after_caps_runaway_values() {
        let v = HeaderValue::from_static("999999");
        assert_eq!(parse_retry_after(&v), Some(MAX_RETRY_AFTER));
    }

    #[test]
    fn jittered_backoff_grows_and_caps() {
        for _ in 0..50 {
            let d1 = jittered_backoff(1);
            let d10 = jittered_backoff(10);
            assert!(d1 >= INITIAL_BACKOFF.mul_f64(0.8));
            assert!(d1 <= INITIAL_BACKOFF.mul_f64(1.2));
            assert!(d10 <= MAX_BACKOFF.mul_f64(1.0 + JITTER_RATIO));
            assert!(d10 >= MAX_BACKOFF.mul_f64(0.5));
        }
    }

    #[test]
    fn jittered_backoff_saturates_on_huge_attempt() {
        // Should not panic on overflow.
        let d = jittered_backoff(u32::MAX);
        assert!(d <= MAX_BACKOFF.mul_f64(1.0 + JITTER_RATIO));
    }
}
