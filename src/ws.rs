use anyhow::{Result, bail};
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{error, info, warn};
use url::Url;

use crate::config::TunnelConfig;

const DEVICE_PORT_LO: u16 = 49_152;
const DEVICE_PORT_HI: u16 = 65_535;

/// Shared map from tunnel_id to (expiry_unix_secs, tunnel_prn).
/// Lives across WebSocket reconnects so the watchdog can close expired tunnels
/// even if the tunnel_closed message was never received.
pub type ActiveTunnels = Arc<Mutex<HashMap<String, (u64, String)>>>;

/// Prepared WireGuard state stored between tunnel_request and tunnel_established.
struct TunnelPrep {
    private_key: String,
    listen_port: u16,
    iface_name: String,
    expires_at: String,
    tunnel_prn: String,
}

pub async fn connect_and_heartbeat(
    api_url: &str,
    token: &str,
    heartbeat_secs: u64,
    tunnel_cfg: TunnelConfig,
    active_tunnels: ActiveTunnels,
    outbox: &mut tokio::sync::mpsc::UnboundedReceiver<String>,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
    rat_available: bool,
) -> Result<()> {
    let ws_url = build_ws_url(api_url, token)?;
    info!("connecting to WebSocket...");

    let (ws_stream, _response) = connect_async(ws_url.as_str()).await?;
    info!("WebSocket connected");

    let (mut write, mut read) = ws_stream.split();

    let hb_msg = serde_json::json!({"type": "heartbeat"});
    write.send(Message::Text(hb_msg.to_string())).await?;
    info!("initial heartbeat sent");

    let caps = serde_json::json!({"type": "capabilities", "tunnels": rat_available});
    write.send(Message::Text(caps.to_string())).await?;
    info!(rat_available, "sent capabilities");

    let mut pending: HashMap<String, TunnelPrep> = HashMap::new();

    loop {
        tokio::select! {
            msg = read.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        let replies = handle_server_message(&text, &mut pending, &tunnel_cfg, &active_tunnels, rat_available).await;
                        for reply in replies {
                            write.send(Message::Text(reply)).await?;
                        }
                    }
                    Some(Ok(Message::Close(_))) => {
                        info!("WebSocket closed by server");
                        return Ok(());
                    }
                    Some(Ok(_)) => {}
                    Some(Err(e)) => {
                        error!("WebSocket error: {e}");
                        bail!("WebSocket error: {e}");
                    }
                    None => {
                        info!("WebSocket stream ended");
                        return Ok(());
                    }
                }
            }
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(heartbeat_secs)) => {
                let hb = serde_json::json!({"type": "heartbeat"});
                if let Err(e) = write.send(Message::Text(hb.to_string())).await {
                    error!("failed to send heartbeat: {e}");
                    bail!("heartbeat send failed: {e}");
                }
            }
            Some(queued) = outbox.recv() => {
                if let Err(e) = write.send(Message::Text(queued)).await {
                    error!("failed to send queued outbox message: {e}");
                    bail!("outbox send failed: {e}");
                }
            }
            _ = shutdown.changed() => {
                info!("graceful shutdown — draining outbox and closing WebSocket");
                // Drain any tunnel_close notifications queued by shutdown_tunnels
                // before shutting down the connection.
                while let Ok(msg) = outbox.try_recv() {
                    if let Err(e) = write.send(Message::Text(msg)).await {
                        warn!("failed to flush outbox during shutdown: {e}");
                        break;
                    }
                }
                let _ = write.send(Message::Close(None)).await;
                return Ok(());
            }
        }
    }
}

/// Close all active tunnels via rat and enqueue `tunnel_close` server
/// notifications into the outbox. Called during graceful shutdown before
/// signaling the WebSocket loop to exit.
pub async fn shutdown_tunnels(
    active_tunnels: &ActiveTunnels,
    rat_socket_path: &str,
    outbox: &tokio::sync::mpsc::UnboundedSender<String>,
) {
    // Drain the map atomically so the watchdog won't also try to close these.
    let tunnels: Vec<(String, String)> = {
        let mut map = active_tunnels.lock().unwrap();
        map.drain().map(|(id, (_, prn))| (id, prn)).collect()
    };

    for (tunnel_id, tunnel_prn) in tunnels {
        info!(tunnel_id, "graceful shutdown — closing tunnel via rat");
        let req = serde_json::json!({"command": "close", "id": tunnel_id});
        match rat_call(rat_socket_path, &req).await {
            Ok(_) => info!(tunnel_id, "graceful shutdown closed tunnel"),
            Err(e) => warn!(tunnel_id, "graceful shutdown rat close failed: {e:#}"),
        }
        // Queue server notification — WS loop drains these before closing.
        let msg =
            serde_json::json!({"type": "tunnel_close", "tunnel_prn": tunnel_prn}).to_string();
        let _ = outbox.send(msg);
    }
}

/// Expiry watchdog — runs independently of the WebSocket connection.
///
/// Every 30 seconds, checks the active tunnel map for any tunnels whose
/// `expires_at` has passed and closes them via rat. This is the fallback
/// for missed `tunnel_closed` messages due to flaky connections or reconnects.
pub async fn expiry_watchdog(
    active_tunnels: ActiveTunnels,
    rat_socket_path: String,
    outbox: tokio::sync::mpsc::UnboundedSender<String>,
) {
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

        let now = unix_now_secs();

        let expired: Vec<(String, String)> = {
            let map = active_tunnels.lock().unwrap();
            // Log each tick so we can confirm the watchdog is running and see stored expiries.
            for (id, (exp, _)) in map.iter() {
                let remaining = if *exp > now { *exp - now } else { 0 };
                info!(tunnel_id = %id, expiry_unix = exp, now, remaining_secs = remaining, "watchdog tick — active tunnel");
            }
            if map.is_empty() {
                info!(now, "watchdog tick — no active tunnels");
            }
            map.iter()
                .filter(|&(_, (exp, _))| *exp <= now)
                .map(|(id, (_, prn))| (id.clone(), prn.clone()))
                .collect()
        };

        for (tunnel_id, tunnel_prn) in expired {
            warn!(tunnel_id, "tunnel TTL elapsed locally — closing interface");
            let req = serde_json::json!({"command": "close", "id": tunnel_id});
            match rat_call(&rat_socket_path, &req).await {
                Ok(_) => info!(tunnel_id, "expiry watchdog closed tunnel"),
                Err(e) => warn!(tunnel_id, "expiry watchdog rat close failed: {e:#}"),
            }
            // Notify server that this device has closed the tunnel. Queued in the
            // outbox so the WS loop sends it when the connection is available.
            let msg = serde_json::json!({"type": "tunnel_close", "tunnel_prn": tunnel_prn})
                .to_string();
            if outbox.send(msg).is_err() {
                warn!(tunnel_id, "expiry watchdog: outbox closed, server notification dropped");
            }
            // Remove regardless of rat result — if it failed the interface is
            // likely already gone. Leaving it in the map would cause repeated
            // close attempts every 30s.
            active_tunnels.lock().unwrap().remove(&tunnel_id);
        }
    }
}

async fn handle_server_message(
    text: &str,
    pending: &mut HashMap<String, TunnelPrep>,
    cfg: &TunnelConfig,
    active_tunnels: &ActiveTunnels,
    rat_available: bool,
) -> Vec<String> {
    let msg: serde_json::Value = match serde_json::from_str(text) {
        Ok(m) => m,
        Err(_) => return vec![],
    };

    match msg["type"].as_str() {
        Some("tunnel_request") => {
            if !rat_available {
                warn!("received tunnel_request but rat is unavailable, sending nack");
                return vec![serde_json::json!({
                    "type": "tunnel_nack",
                    "tunnel_id": msg["tunnel_id"],
                    "reason": "tunnels_not_supported"
                })
                .to_string()];
            }

            let tunnel_id = msg["tunnel_id"].as_str().unwrap_or("").to_string();
            let tunnel_prn = msg["tunnel_prn"].as_str().unwrap_or("").to_string();
            let expires_at = msg["expires_at"].as_str().unwrap_or("").to_string();
            info!(tunnel_id, "received tunnel_request");

            match prepare_tunnel(&tunnel_id, cfg).await {
                Ok(prep) => {
                    let ack = serde_json::json!({"type": "tunnel_ack", "tunnel_id": tunnel_id})
                        .to_string();

                    let configure = serde_json::json!({
                        "type": "tunnel_configure",
                        "tunnel_prn": tunnel_prn,
                        "device_public_key": derive_public_key(&prep.private_key).unwrap_or_default(),
                        "device_endpoint_ip": outbound_ip(),
                        "device_endpoint_port": prep.listen_port,
                        "device_proxy_port": cfg.device_proxy_port,
                        "cidr_blocks": cfg.cidr_blocks,
                    })
                    .to_string();

                    let tunnel_id_clone = tunnel_id.clone();
                    let prep = TunnelPrep { expires_at, tunnel_prn, ..prep };
                    pending.insert(tunnel_id, prep);
                    info!(tunnel_id = tunnel_id_clone, "sent tunnel_ack + tunnel_configure");
                    vec![ack, configure]
                }
                Err(e) => {
                    error!(tunnel_id, "failed to prepare tunnel: {e:#}");
                    vec![]
                }
            }
        }

        Some("tunnel_established") => {
            if !rat_available {
                warn!("received tunnel_established but rat is unavailable, ignoring");
                return vec![];
            }

            let tunnel_id = msg["tunnel_id"].as_str().unwrap_or("").to_string();
            info!(tunnel_id, "tunnel_established received");

            let Some(prep) = pending.remove(&tunnel_id) else {
                warn!(tunnel_id, "got tunnel_established for unknown tunnel");
                return vec![];
            };

            let device_tunnel_ip = msg["device_tunnel_ip"].as_str().unwrap_or("");
            let server_public_key = msg["server_public_key"].as_str().unwrap_or("");
            let server_tunnel_ip = msg["server_tunnel_ip"].as_str().unwrap_or("");
            let relay_node_address = msg["relay_node_address"].as_str().unwrap_or("");
            let server_listen_port = msg["server_listen_port"].as_u64().unwrap_or(0) as u16;

            let ttl_secs = remaining_ttl_secs(&prep.expires_at);

            let open_req = serde_json::json!({
                "command": "open",
                "id": tunnel_id,
                "interface": {
                    "id": prep.iface_name,
                    "address": format!("{}/32", device_tunnel_ip),
                    "listen_port": prep.listen_port,
                    "private_key": prep.private_key,
                    "table": "auto"
                },
                "peer": {
                    "public_key": server_public_key,
                    "allowed_ips": [format!("{}/32", server_tunnel_ip)],
                    "endpoint": relay_node_address,
                    "endpoint_port": server_listen_port,
                    "persistent_keepalive": 25
                },
                "ttl_secs": ttl_secs,
            });

            if let Err(e) = rat_call(&cfg.rat_socket_path, &open_req).await {
                error!(tunnel_id, "rat open failed: {e:#}");
            } else {
                info!(tunnel_id, iface = %prep.iface_name, "WireGuard interface up");
                // Track in active map so the expiry watchdog can close it if
                // the tunnel_closed message is ever missed.
                let expiry = parse_expiry_unix(&prep.expires_at);
                info!(tunnel_id, expires_at = %prep.expires_at, expiry_unix = expiry, "tracking tunnel in watchdog map");
                active_tunnels.lock().unwrap().insert(tunnel_id, (expiry, prep.tunnel_prn));
            }
            vec![]
        }

        Some("tunnel_closed") => {
            if !rat_available {
                warn!("received tunnel_closed but rat is unavailable, ignoring");
                return vec![];
            }

            let tunnel_id = msg["tunnel_id"].as_str().unwrap_or("").to_string();
            pending.remove(&tunnel_id);
            active_tunnels.lock().unwrap().remove(&tunnel_id);
            info!(tunnel_id, "tunnel_closed — tearing down interface");
            let req = serde_json::json!({"command": "close", "id": tunnel_id});
            if let Err(e) = rat_call(&cfg.rat_socket_path, &req).await {
                warn!(tunnel_id, "rat close failed (may already be down): {e:#}");
            }
            vec![]
        }

        Some("tunnel_extended") => {
            if !rat_available {
                warn!("received tunnel_extended but rat is unavailable, ignoring");
                return vec![];
            }

            let tunnel_id = msg["tunnel_id"].as_str().unwrap_or("").to_string();
            let expires_at = msg["expires_at"].as_str().unwrap_or("");
            let secs = remaining_ttl_secs(expires_at);
            info!(tunnel_id, secs, "tunnel_extended");
            // Update the watchdog's expiry so it doesn't close a tunnel that was
            // just extended. Preserve the existing tunnel_prn.
            let expiry = parse_expiry_unix(expires_at);
            {
                let mut map = active_tunnels.lock().unwrap();
                let prn = map.get(&tunnel_id).map(|(_, p)| p.clone()).unwrap_or_default();
                map.insert(tunnel_id.clone(), (expiry, prn));
            }
            let req = serde_json::json!({"command": "extend", "id": tunnel_id, "secs": secs});
            if let Err(e) = rat_call(&cfg.rat_socket_path, &req).await {
                warn!(tunnel_id, "rat extend failed: {e:#}");
            }
            vec![]
        }

        _ => vec![],
    }
}

/// Call rat over Unix socket, return the response JSON.
async fn rat_call(socket_path: &str, request: &serde_json::Value) -> Result<serde_json::Value> {
    let stream = UnixStream::connect(socket_path).await?;
    let (reader, mut writer) = stream.into_split();
    let mut payload = serde_json::to_string(request)?;
    payload.push('\n');
    writer.write_all(payload.as_bytes()).await?;
    writer.shutdown().await?;

    let mut lines = BufReader::new(reader).lines();
    let line = lines
        .next_line()
        .await?
        .ok_or_else(|| anyhow::anyhow!("rat returned no response"))?;
    let resp: serde_json::Value = serde_json::from_str(&line)?;
    if resp["ok"].as_bool() != Some(true) {
        bail!("rat error: {}", resp["error"].as_str().unwrap_or("unknown"));
    }
    Ok(resp)
}

/// Prepare a tunnel: find an available UDP port, generate a WireGuard keypair.
async fn prepare_tunnel(tunnel_id: &str, cfg: &TunnelConfig) -> Result<TunnelPrep> {
    // Ask rat for an available UDP port; use config range if set, else defaults.
    let lo = cfg.wg_port_lo.unwrap_or(DEVICE_PORT_LO);
    let hi = cfg.wg_port_hi.unwrap_or(DEVICE_PORT_HI);
    let req = serde_json::json!({
        "command": "find_port",
        "lo": lo,
        "hi": hi,
    });
    let resp = rat_call(&cfg.rat_socket_path, &req).await?;
    let listen_port = resp["data"]["port"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("rat find_port returned no port"))? as u16;

    // Generate WireGuard private key in pure Rust (no wg binary required)
    let private_key = generate_wg_private_key();

    // Interface name: "avo" (3 chars) + last 12 chars of stripped tunnel_id = 15 chars max.
    // Strip hyphens first, then take the LAST 12 chars (random bits for UUIDv7) rather than
    // the first 12 (timestamp bits), to avoid collisions for same-millisecond UUIDs.
    let stripped: String = tunnel_id.chars().filter(|c| *c != '-').collect();
    let suffix = if stripped.len() >= 12 {
        stripped[stripped.len() - 12..].to_string()
    } else {
        stripped
    };
    let iface_name = format!("avo{suffix}");

    Ok(TunnelPrep {
        private_key,
        listen_port,
        iface_name,
        expires_at: String::new(),
        tunnel_prn: String::new(),
    })
}

/// Generate a WireGuard private key (base64-encoded X25519 scalar) in pure Rust.
fn generate_wg_private_key() -> String {
    use rand::RngCore;
    use base64::Engine;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    // Clamp per RFC 7748 / WireGuard spec
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Derive the WireGuard public key from a base64-encoded private key in pure Rust.
fn derive_public_key(private_key: &str) -> Result<String> {
    use base64::Engine;
    use x25519_dalek::{PublicKey, StaticSecret};
    let bytes = base64::engine::general_purpose::STANDARD.decode(private_key.trim())?;
    let secret: StaticSecret = StaticSecret::from(
        <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| anyhow::anyhow!("private key must be 32 bytes"))?,
    );
    let public: PublicKey = PublicKey::from(&secret);
    Ok(base64::engine::general_purpose::STANDARD.encode(public.as_bytes()))
}

/// Determine the device's outbound IP by connecting a UDP socket (no packets sent).
fn outbound_ip() -> String {
    use std::net::UdpSocket;
    let Ok(socket) = UdpSocket::bind("0.0.0.0:0") else {
        return "0.0.0.0".to_string();
    };
    let _ = socket.connect("8.8.8.8:80");
    socket
        .local_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "0.0.0.0".to_string())
}

/// Parse RFC 3339 timestamp and return seconds until expiry (min 60).
fn remaining_ttl_secs(expires_at: &str) -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(expires_at) {
        let exp = dt.timestamp() as u64;
        if exp > now + 60 {
            return exp - now;
        }
    }
    3600
}

/// Parse RFC 3339 timestamp and return the absolute Unix timestamp (seconds).
/// Used by the expiry watchdog to compare against the current time.
fn parse_expiry_unix(expires_at: &str) -> u64 {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(expires_at) {
        return dt.timestamp().max(0) as u64;
    }
    // Fallback: 1 hour from now — same conservatism as remaining_ttl_secs.
    unix_now_secs() + 3600
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn build_ws_url(api_url: &str, token: &str) -> Result<Url> {
    let mut url = Url::parse(api_url)?;
    match url.scheme() {
        "http" => url.set_scheme("ws").unwrap(),
        "https" => url.set_scheme("wss").unwrap(),
        s if s == "ws" || s == "wss" => {}
        other => bail!("unsupported URL scheme: {other}"),
    }
    url.set_path("/ws/device");
    url.query_pairs_mut().append_pair("token", token);
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_expiry_unix ---

    #[test]
    fn parse_expiry_unix_returns_correct_timestamp() {
        // 2030-01-01T00:00:00Z = 1893456000
        let ts = parse_expiry_unix("2030-01-01T00:00:00Z");
        assert_eq!(ts, 1_893_456_000);
    }

    #[test]
    fn parse_expiry_unix_handles_offset_timestamps() {
        // 2030-01-01T01:00:00+01:00 is the same instant as 2030-01-01T00:00:00Z
        let ts = parse_expiry_unix("2030-01-01T01:00:00+01:00");
        assert_eq!(ts, 1_893_456_000);
    }

    #[test]
    fn parse_expiry_unix_falls_back_on_invalid_input() {
        let before = unix_now_secs();
        let ts = parse_expiry_unix("not-a-date");
        let after = unix_now_secs();
        // Fallback = now + 3600; allow a 2s window for test execution time
        assert!(ts >= before + 3600);
        assert!(ts <= after + 3600 + 2);
    }

    #[test]
    fn parse_expiry_unix_falls_back_on_empty_string() {
        let before = unix_now_secs();
        let ts = parse_expiry_unix("");
        let after = unix_now_secs();
        assert!(ts >= before + 3600);
        assert!(ts <= after + 3600 + 2);
    }

    #[test]
    fn parse_expiry_unix_clamps_past_timestamps_to_zero() {
        // Unix epoch = 0; parse_expiry_unix uses .max(0) so negatives become 0
        let ts = parse_expiry_unix("1970-01-01T00:00:00Z");
        assert_eq!(ts, 0);
    }

    // --- remaining_ttl_secs ---

    #[test]
    fn remaining_ttl_secs_returns_fallback_for_invalid_input() {
        assert_eq!(remaining_ttl_secs("bad-date"), 3600);
    }

    #[test]
    fn remaining_ttl_secs_returns_fallback_for_expired_timestamp() {
        // Already in the past — should return fallback 3600
        assert_eq!(remaining_ttl_secs("2020-01-01T00:00:00Z"), 3600);
    }

    #[test]
    fn remaining_ttl_secs_returns_seconds_for_future_timestamp() {
        // A timestamp 2 hours in the future should return ~7200s (within 5s tolerance)
        let two_hours = unix_now_secs() + 7200;
        let ts_str = chrono::DateTime::from_timestamp(two_hours as i64, 0)
            .unwrap()
            .to_rfc3339();
        let secs = remaining_ttl_secs(&ts_str);
        // Should be approximately 7200, allow a small window for test execution
        assert!(secs > 7190 && secs <= 7200, "expected ~7200, got {secs}");
    }

    // --- build_ws_url ---

    #[test]
    fn build_ws_url_upgrades_http_to_ws() {
        let url = build_ws_url("http://localhost:4000", "mytoken").unwrap();
        assert_eq!(url.scheme(), "ws");
        assert_eq!(url.path(), "/ws/device");
        assert!(url.as_str().contains("token=mytoken"));
    }

    #[test]
    fn build_ws_url_upgrades_https_to_wss() {
        let url = build_ws_url("https://connect.example.com", "tok").unwrap();
        assert_eq!(url.scheme(), "wss");
    }

    #[test]
    fn build_ws_url_preserves_wss_scheme() {
        let url = build_ws_url("wss://connect.example.com", "tok").unwrap();
        assert_eq!(url.scheme(), "wss");
    }
}
