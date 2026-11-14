use anyhow::{Result, bail};
use rumqttc::{AsyncClient, Event, MqttOptions, Packet, QoS};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tracing::{error, info, warn};

use crate::config::{MqttConfig, RuntimeConfig, TunnelConfig};

const DEVICE_PORT_LO: u16 = 49_152;
const DEVICE_PORT_HI: u16 = 65_535;

/// Serialises runtime updates: one runs at a time, and a nudge that arrives
/// while one is running buys exactly one more pass after it.
///
/// Process-wide rather than threaded through `connect_and_run`: the update runs
/// on a detached task and has to outlive the MQTT connection that received the
/// nudge, so a reconnect mid-update does not start a second one.
static UPDATES: UpdateGate = UpdateGate::new();

struct UpdateGate {
    in_flight: AtomicBool,
    requested: AtomicBool,
}

impl UpdateGate {
    const fn new() -> Self {
        Self {
            in_flight: AtomicBool::new(false),
            requested: AtomicBool::new(false),
        }
    }

    /// Record a nudge. Returns the slot when no update is running; otherwise
    /// the running one sees `requested` and does another pass.
    fn nudge(&'static self) -> Option<UpdateSlot> {
        self.requested.store(true, Ordering::SeqCst);
        self.claim()
    }

    fn claim(&'static self) -> Option<UpdateSlot> {
        self.in_flight
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
            .then(|| UpdateSlot(self))
    }

    /// Run `pass` until no nudge arrived during the last one, then release
    /// the slot. A pass that ends without activating anything doesn't restart
    /// conn, and Connect won't re-nudge, so a dropped nudge would be lost.
    async fn drain<F, Fut>(&'static self, slot: UpdateSlot, mut pass: F)
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let mut slot = Some(slot);
        while let Some(held) = slot {
            while self.requested.swap(false, Ordering::SeqCst) {
                pass().await;
            }
            drop(held);
            // A nudge landing between the last swap and the release found the
            // slot taken and returned; pick it up here.
            slot = if self.requested.load(Ordering::SeqCst) {
                self.claim()
            } else {
                None
            };
        }
    }
}

/// Held while updates run; releases the slot on drop, including on a panic,
/// so a failed update can never disable updates for the process lifetime.
struct UpdateSlot(&'static UpdateGate);

impl Drop for UpdateSlot {
    fn drop(&mut self) {
        self.0.in_flight.store(false, Ordering::SeqCst);
    }
}

/// Shared map from tunnel_id to (expiry_unix_secs, tunnel_prn).
/// Lives across MQTT reconnects so the watchdog can close expired tunnels
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

/// The `tunnel_ack` + `tunnel_configure` pair for a prepared tunnel.
fn tunnel_ack_and_configure(tunnel_id: &str, prep: &TunnelPrep, cfg: &TunnelConfig) -> Vec<String> {
    let ack = serde_json::json!({"type": "tunnel_ack", "tunnel_id": tunnel_id}).to_string();
    let configure = serde_json::json!({
        "type": "tunnel_configure",
        "tunnel_id": tunnel_id,
        "tunnel_prn": prep.tunnel_prn,
        "device_public_key": derive_public_key(&prep.private_key).unwrap_or_default(),
        "device_endpoint_ip": outbound_ip(),
        "device_endpoint_port": prep.listen_port,
        "device_proxy_port": cfg.device_proxy_port,
        "cidr_blocks": cfg.cidr_blocks,
    })
    .to_string();
    vec![ack, configure]
}

/// Largest MQTT packet accepted or sent. Fits both brokers Connect runs:
/// EMQX's default `max_packet_size` (1 MiB) and RabbitMQ's far larger
/// authenticated limit. rumqttc grows its read buffer on demand, so this is
/// a ceiling, not an allocation; steady-state memory is unchanged.
pub(crate) const MAX_PACKET: usize = 1 << 20;

#[allow(clippy::too_many_arguments)]
pub async fn connect_and_run(
    cfg: &MqttConfig,
    keepalive_secs: u64,
    tunnel_cfg: TunnelConfig,
    active_tunnels: ActiveTunnels,
    outbox: &mut tokio::sync::mpsc::UnboundedReceiver<String>,
    handler_events: &mut tokio::sync::mpsc::Receiver<String>,
    outbox_tx: &tokio::sync::mpsc::UnboundedSender<String>,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
    rat_available: Arc<AtomicBool>,
    api_url: &str,
    tuf_url: Option<&str>,
    artifacts_url: Option<&str>,
    runtime: Option<RuntimeConfig>,
    avocadoctl_socket: &str,
    local_handler: Option<&tokio::sync::mpsc::Sender<String>>,
) -> Result<()> {
    // Read root version from avocadoctl (best-effort, don't fail if unavailable)
    let root_version = varlink_get_root_version(avocadoctl_socket).await;
    if let Some(v) = root_version {
        info!(root_version = v, "read root.json version from avocadoctl");
    }
    // Query active runtime from avocadoctl (overrides config if available)
    let runtime = match varlink_get_active_runtime(avocadoctl_socket).await {
        Some(rt) => {
            info!(runtime_name = ?rt.name, runtime_version = ?rt.version, "read active runtime from avocadoctl");
            Some(rt)
        }
        None => {
            if runtime.is_some() {
                info!("using runtime from config");
            }
            runtime
        }
    };
    let device_id = &cfg.username;
    let cmd_topic = format!("cmd/{device_id}");
    let event_topic = format!("event/{device_id}");
    let presence_topic = format!("presence/{device_id}");

    let mut options = MqttOptions::new(&cfg.client_id, &cfg.host, cfg.port);
    options.set_credentials(&cfg.username, &cfg.password);
    options.set_keep_alive(Duration::from_secs(keepalive_secs.max(10)));
    // rumqttc defaults to 10 KiB each way and drops the connection on a
    // bigger packet; with a persistent session the broker then redelivers
    // the same QoS1 message forever.
    options.set_max_packet_size(MAX_PACKET, MAX_PACKET);
    // Persistent session — EMQX queues cmd/+ messages while device is offline.
    options.set_clean_session(false);
    // LWT: broker publishes 0x00 to presence/{device_id} on unexpected disconnect.
    options.set_last_will(rumqttc::LastWill::new(
        &presence_topic,
        [0x00u8],
        QoS::AtMostOnce,
        false,
    ));

    // TLS: explicit from claim response, or auto-detect by port (8883 = TLS).
    let use_tls = cfg.tls.unwrap_or(cfg.port == 8883);
    if use_tls {
        use rumqttc::tokio_rustls::rustls;
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        options.set_transport(rumqttc::Transport::tls_with_config(
            rumqttc::TlsConfiguration::Rustls(Arc::new(tls_config)),
        ));
        info!("MQTT TLS enabled");
    }

    let (client, mut eventloop) = AsyncClient::new(options, 64);

    // Poll the eventloop in a background task — rumqttc requires continuous polling
    // to process both outgoing publishes and incoming packets.
    // Unbounded so el_task never stops polling: a full channel here stalled
    // the eventloop, which stopped draining the request queue that
    // client.publish waits on. It carries only what `forwarded` lets through,
    // so it holds at most the broker's queued backlog.
    let (evt_tx, mut evt_rx) =
        tokio::sync::mpsc::unbounded_channel::<Result<Event, rumqttc::ConnectionError>>();
    let el_task = tokio::spawn(async move {
        loop {
            let result = eventloop.poll().await;
            let is_err = result.is_err();
            // Forward only what the loop acts on. Forwarding every publish's
            // Outgoing/PubAck events let a burst fill evt_tx while the loop
            // sat in client.publish, deadlocking both sides.
            if !forwarded(&result) {
                continue;
            }
            if evt_tx.send(result).is_err() {
                break;
            }
            if is_err {
                break;
            }
        }
    });

    info!(host = %cfg.host, port = cfg.port, tls = use_tls, client_id = %cfg.client_id, "connecting to MQTT...");

    let mut pending: HashMap<String, TunnelPrep> = HashMap::new();

    loop {
        tokio::select! {
            result = evt_rx.recv() => {
                match result {
                    None => {
                        // el_task exited — connection dropped or send channel closed.
                        bail!("MQTT eventloop exited unexpectedly");
                    }
                    Some(Ok(Event::Incoming(Packet::ConnAck(_)))) => {
                        info!("MQTT connected");
                        client.subscribe(&cmd_topic, QoS::AtLeastOnce).await?;
                        // Publish online presence.
                        client
                            .publish(&presence_topic, QoS::AtMostOnce, false, [0x01u8])
                            .await?;
                        // Send device shadow: capabilities + config + runtime + tuf reported on every connect.
                        let mut shadow = serde_json::json!({
                            "type": "shadow",
                            "tunnels": rat_available.load(Ordering::Relaxed),
                            "keepalive_secs": keepalive_secs,
                        });
                        if let Some(rt) = &runtime {
                            shadow["runtime_id"] = serde_json::json!(rt.id);
                            shadow["runtime_name"] = serde_json::json!(rt.name);
                            shadow["runtime_version"] = serde_json::json!(rt.version);
                        }
                        if let Some(v) = root_version {
                            shadow["root_version"] = serde_json::json!(v);
                        }
                        client
                            .publish(&event_topic, QoS::AtLeastOnce, false, shadow.to_string())
                            .await?;
                        info!(topic = %cmd_topic, "MQTT subscribed");
                    }
                    Some(Ok(Event::Incoming(Packet::Publish(publish)))) => {
                        let text = match std::str::from_utf8(&publish.payload) {
                            Ok(s) => s.to_string(),
                            Err(_) => {
                                warn!("received non-UTF8 MQTT payload, ignoring");
                                continue;
                            }
                        };
                        let replies = handle_server_message(
                            &text,
                            &mut pending,
                            &tunnel_cfg,
                            &active_tunnels,
                            &rat_available,
                            api_url,
                            &cfg.password,
                            tuf_url,
                            artifacts_url,
                            &runtime,
                            avocadoctl_socket,
                            outbox_tx,
                            keepalive_secs,
                            local_handler,
                        )
                        .await;
                        for reply in replies {
                            if let Err(e) = client
                                .publish(&event_topic, QoS::AtLeastOnce, false, reply)
                                .await
                            {
                                error!("failed to publish reply: {e}");
                            }
                        }
                    }
                    Some(Ok(Event::Incoming(Packet::Disconnect))) => {
                        info!("MQTT disconnected by broker");
                        el_task.abort();
                        return Ok(());
                    }
                    Some(Ok(_)) => {}
                    Some(Err(e)) => {
                        error!("MQTT connection error: {e}");
                        el_task.abort();
                        bail!("MQTT connection error: {e}");
                    }
                }
            }
            Some(event) = handler_events.recv() => {
                if let Err(e) = client
                    .publish(&event_topic, QoS::AtLeastOnce, false, event)
                    .await
                {
                    error!("failed to publish local handler event: {e}");
                    el_task.abort();
                    bail!("handler event publish failed: {e}");
                }
            }
            Some(queued) = outbox.recv() => {
                if let Err(e) = client
                    .publish(&event_topic, QoS::AtLeastOnce, false, queued)
                    .await
                {
                    error!("failed to publish outbox message: {e}");
                    el_task.abort();
                    bail!("outbox publish failed: {e}");
                }
            }
            _ = shutdown.changed() => {
                info!("graceful shutdown — draining outbox and disconnecting MQTT");
                // Drain tunnel_close notifications queued by shutdown_tunnels.
                while let Ok(msg) = outbox.try_recv() {
                    if let Err(e) = client
                        .publish(&event_topic, QoS::AtLeastOnce, false, msg)
                        .await
                    {
                        warn!("failed to flush outbox during shutdown: {e}");
                        break;
                    }
                }
                // Publish offline presence explicitly (clean disconnect won't trigger LWT).
                let _ = client
                    .publish(&presence_topic, QoS::AtMostOnce, false, [0x00u8])
                    .await;
                let _ = client.disconnect().await;
                el_task.abort();
                return Ok(());
            }
        }
    }
}

/// Eventloop results the connection loop acts on; everything else is dropped
/// in the eventloop task so it can never back up the channel.
fn forwarded(result: &Result<Event, rumqttc::ConnectionError>) -> bool {
    matches!(
        result,
        Err(_)
            | Ok(Event::Incoming(
                Packet::ConnAck(_) | Packet::Publish(_) | Packet::Disconnect
            ))
    )
}

/// Build a `tunnel_close` server notification for a tunnel.
///
/// The server route matches `%{"type" => "tunnel_close", "tunnel_id" => id}`
/// and uses the value for `Relay.get_tunnel(id)`, the same `tunnel_id` key
/// every other tunnel_* event uses. The value is the tunnel id, not the prn.
fn tunnel_close_msg(tunnel_id: &str) -> String {
    serde_json::json!({"type": "tunnel_close", "tunnel_id": tunnel_id}).to_string()
}

/// Close all active tunnels via rat and enqueue `tunnel_close` server
/// notifications into the outbox. Called during graceful shutdown before
/// signaling the MQTT loop to exit.
pub async fn shutdown_tunnels(
    active_tunnels: &ActiveTunnels,
    tunnel_cfg: &TunnelConfig,
    outbox: &tokio::sync::mpsc::UnboundedSender<String>,
) {
    // Drain the map atomically so the watchdog won't also try to close these.
    let tunnels: Vec<String> = {
        let mut map = active_tunnels.lock().unwrap();
        map.drain().map(|(id, _)| id).collect()
    };

    for tunnel_id in tunnels {
        info!(tunnel_id, "graceful shutdown — closing tunnel via rat");
        let req = serde_json::json!({"command": "close", "id": tunnel_id});
        match rat_call(tunnel_cfg, &req).await {
            Ok(_) => info!(tunnel_id, "graceful shutdown closed tunnel"),
            Err(e) => warn!(tunnel_id, "graceful shutdown rat close failed: {e:#}"),
        }
        // Queue server notification — MQTT loop drains these before closing.
        let msg = tunnel_close_msg(&tunnel_id);
        let _ = outbox.send(msg);
    }
}

/// Expiry watchdog — runs independently of the MQTT connection.
///
/// Every 30 seconds, checks the active tunnel map for any tunnels whose
/// `expires_at` has passed and closes them via rat. This is the fallback
/// for missed `tunnel_closed` messages due to flaky connections or reconnects.
pub async fn expiry_watchdog(
    active_tunnels: ActiveTunnels,
    tunnel_cfg: TunnelConfig,
    outbox: tokio::sync::mpsc::UnboundedSender<String>,
) {
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;

        let now = unix_now_secs();

        let expired: Vec<String> = {
            let map = active_tunnels.lock().unwrap();
            for (id, (exp, _)) in map.iter() {
                let remaining = (*exp).saturating_sub(now);
                info!(tunnel_id = %id, expiry_unix = exp, now, remaining_secs = remaining, "watchdog tick — active tunnel");
            }
            if map.is_empty() {
                info!(now, "watchdog tick — no active tunnels");
            }
            map.iter()
                .filter(|&(_, (exp, _))| *exp <= now)
                .map(|(id, _)| id.clone())
                .collect()
        };

        for tunnel_id in expired {
            warn!(tunnel_id, "tunnel TTL elapsed locally — closing interface");
            let req = serde_json::json!({"command": "close", "id": tunnel_id});
            match rat_call(&tunnel_cfg, &req).await {
                Ok(_) => info!(tunnel_id, "expiry watchdog closed tunnel"),
                Err(e) => warn!(tunnel_id, "expiry watchdog rat close failed: {e:#}"),
            }
            let msg = tunnel_close_msg(&tunnel_id);
            if outbox.send(msg).is_err() {
                warn!(
                    tunnel_id,
                    "expiry watchdog: outbox closed, server notification dropped"
                );
            }
            active_tunnels.lock().unwrap().remove(&tunnel_id);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_server_message(
    text: &str,
    pending: &mut HashMap<String, TunnelPrep>,
    cfg: &TunnelConfig,
    active_tunnels: &ActiveTunnels,
    rat_available: &Arc<AtomicBool>,
    _api_url: &str,
    jwt: &str,
    tuf_url: Option<&str>,
    artifacts_url: Option<&str>,
    _runtime: &Option<RuntimeConfig>,
    avocadoctl_socket: &str,
    outbox_tx: &tokio::sync::mpsc::UnboundedSender<String>,
    keepalive_secs: u64,
    local_handler: Option<&tokio::sync::mpsc::Sender<String>>,
) -> Vec<String> {
    let msg: serde_json::Value = match serde_json::from_str(text) {
        Ok(m) => m,
        Err(_) => return vec![],
    };

    // Integer type codes: minimal payload for cellular/metered devices.
    // type=0 → runtime update available. TUF and artifact URLs come from device
    // config (set during provisioning) — the API is not in the runtime fetch path.
    if msg["type"].as_u64() == Some(0) {
        match (tuf_url, artifacts_url) {
            (Some(tuf), Some(artifacts)) => {
                // A nudge carries no target — it just means "fetch whatever your
                // TUF repo now serves". Running two at once would duplicate the
                // download and race on the runtime directory and active symlink,
                // so a nudge mid-update queues one more pass instead.
                let Some(slot) = UPDATES.nudge() else {
                    info!("runtime update in progress — will check again after it");
                    return vec![];
                };

                info!(
                    tuf_url = tuf,
                    artifacts_url = artifacts,
                    "runtime update available — calling avocadoctl via varlink"
                );
                let tuf = tuf.to_string();
                let artifacts = artifacts.to_string();
                let jwt = jwt.to_string();
                let socket = avocadoctl_socket.to_string();
                let tx = outbox_tx.clone();
                let runtime_clone = _runtime.clone();
                let keepalive = keepalive_secs;
                let rat = rat_available.clone();
                tokio::spawn(UPDATES.drain(slot, move || {
                    let (socket, tuf, jwt, artifacts) =
                        (socket.clone(), tuf.clone(), jwt.clone(), artifacts.clone());
                    let (tx, runtime_clone, rat) = (tx.clone(), runtime_clone.clone(), rat.clone());
                    async move {
                    let event = match varlink_add_from_url(&socket, &tuf, &jwt, Some(&artifacts))
                        .await
                    {
                        Ok(()) => {
                            info!("runtime update applied successfully");
                            // Re-read root version and active runtime after update, send updated shadow
                            let new_rv = varlink_get_root_version(&socket).await;
                            let new_rt = varlink_get_active_runtime(&socket).await;
                            let mut shadow = serde_json::json!({
                                "type": "shadow",
                                "tunnels": rat.load(Ordering::Relaxed),
                                "keepalive_secs": keepalive,
                            });
                            if let Some(v) = new_rv {
                                info!(root_version = v, "re-read root version after update");
                                shadow["root_version"] = serde_json::json!(v);
                            }
                            if let Some(ref rt) = new_rt {
                                info!(runtime_name = ?rt.name, runtime_version = ?rt.version, "re-read active runtime after update");
                                shadow["runtime_id"] = serde_json::json!(rt.id);
                                shadow["runtime_name"] = serde_json::json!(rt.name);
                                shadow["runtime_version"] = serde_json::json!(rt.version);
                            } else if let Some(rt) = &runtime_clone {
                                shadow["runtime_id"] = serde_json::json!(rt.id);
                                shadow["runtime_name"] = serde_json::json!(rt.name);
                                shadow["runtime_version"] = serde_json::json!(rt.version);
                            }
                            let _ = tx.send(shadow.to_string());
                            serde_json::json!({"type": "update_result", "success": true})
                        }
                        Err(e) => {
                            warn!("runtime update failed: {e}");
                            serde_json::json!({"type": "update_result", "success": false, "error": e.to_string()})
                        }
                    };
                    let _ = tx.send(event.to_string());
                    }
                }));
            }
            _ => warn!(
                "runtime update available but tuf_url/artifacts_url not set in config; \
                 add them to config.toml to enable runtime updates"
            ),
        }
        return vec![];
    }

    match msg["type"].as_str() {
        Some("tunnel_request") => {
            if !rat_available.load(Ordering::Relaxed) {
                warn!("received tunnel_request but rat is unavailable, sending nack");
                return vec![
                    serde_json::json!({
                        "type": "tunnel_nack",
                        "tunnel_id": msg["tunnel_id"],
                        "reason": "tunnels_not_supported"
                    })
                    .to_string(),
                ];
            }

            let tunnel_id = msg["tunnel_id"].as_str().unwrap_or("").to_string();
            let tunnel_prn = msg["tunnel_prn"].as_str().unwrap_or("").to_string();
            let expires_at = msg["expires_at"].as_str().unwrap_or("").to_string();
            info!(tunnel_id, "received tunnel_request");

            // A repeat (the server re-sends until the state moves) gets the same
            // answer. Preparing again would pick a new key and port that the
            // server, already past `requested`, would never learn.
            if let Some(prep) = pending.get(&tunnel_id) {
                info!(
                    tunnel_id,
                    "repeated tunnel_request; re-sending the same ack + configure"
                );
                return tunnel_ack_and_configure(&tunnel_id, prep, cfg);
            }

            match prepare_tunnel(&tunnel_id, cfg).await {
                Ok(prep) => {
                    let prep = TunnelPrep {
                        expires_at,
                        tunnel_prn,
                        ..prep
                    };
                    let replies = tunnel_ack_and_configure(&tunnel_id, &prep, cfg);
                    info!(tunnel_id, "sent tunnel_ack + tunnel_configure");
                    pending.insert(tunnel_id, prep);
                    replies
                }
                Err(e) => {
                    // Tell the server, or the tunnel sits at "requested"
                    // until it expires with no reason anywhere but here.
                    error!(tunnel_id, "failed to prepare tunnel: {e:#}");
                    vec![
                        serde_json::json!({
                            "type": "tunnel_nack",
                            "tunnel_id": tunnel_id,
                            "reason": format!("prepare_failed: {e:#}"),
                        })
                        .to_string(),
                    ]
                }
            }
        }

        Some("tunnel_established") => {
            if !rat_available.load(Ordering::Relaxed) {
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

            if let Err(e) = rat_call(cfg, &open_req).await {
                error!(tunnel_id, "rat open failed: {e:#}");
            } else {
                info!(tunnel_id, iface = %prep.iface_name, "WireGuard interface up");
                let expiry = parse_expiry_unix(&prep.expires_at);
                info!(tunnel_id, expires_at = %prep.expires_at, expiry_unix = expiry, "tracking tunnel in watchdog map");
                active_tunnels
                    .lock()
                    .unwrap()
                    .insert(tunnel_id, (expiry, prep.tunnel_prn));
            }
            vec![]
        }

        Some("tunnel_closed") => {
            if !rat_available.load(Ordering::Relaxed) {
                warn!("received tunnel_closed but rat is unavailable, ignoring");
                return vec![];
            }

            let tunnel_id = msg["tunnel_id"].as_str().unwrap_or("").to_string();
            pending.remove(&tunnel_id);
            active_tunnels.lock().unwrap().remove(&tunnel_id);
            info!(tunnel_id, "tunnel_closed — tearing down interface");
            let req = serde_json::json!({"command": "close", "id": tunnel_id});
            if let Err(e) = rat_call(cfg, &req).await {
                warn!(tunnel_id, "rat close failed (may already be down): {e:#}");
            }
            vec![]
        }

        Some("tunnel_extended") => {
            if !rat_available.load(Ordering::Relaxed) {
                warn!("received tunnel_extended but rat is unavailable, ignoring");
                return vec![];
            }

            let tunnel_id = msg["tunnel_id"].as_str().unwrap_or("").to_string();
            let expires_at = msg["expires_at"].as_str().unwrap_or("");
            let secs = remaining_ttl_secs(expires_at);
            info!(tunnel_id, secs, "tunnel_extended");
            let expiry = parse_expiry_unix(expires_at);
            {
                let mut map = active_tunnels.lock().unwrap();
                let prn = map
                    .get(&tunnel_id)
                    .map(|(_, p)| p.clone())
                    .unwrap_or_default();
                map.insert(tunnel_id.clone(), (expiry, prn));
            }
            let req = serde_json::json!({"command": "extend", "id": tunnel_id, "secs": secs});
            if let Err(e) = rat_call(cfg, &req).await {
                warn!(tunnel_id, "rat extend failed: {e:#}");
            }
            vec![]
        }

        // Not ours: hand it to the local handler, if one is configured.
        Some(ty) => {
            if let Some(tx) = local_handler
                && tx.try_send(msg.to_string()).is_err()
            {
                warn!(ty, "local handler queue full or closed, message dropped");
            }
            vec![]
        }
        None => vec![],
    }
}

/// Query the device's root.json version via avocadoctl's varlink Show method.
///
/// Returns `Some(version)` if root.json exists, `None` if unavailable.
/// Best-effort — failures are logged but don't prevent startup.
pub async fn varlink_get_root_version(socket_addr: &str) -> Option<u64> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let path = socket_addr.strip_prefix("unix:").unwrap_or(socket_addr);

    let mut stream = match tokio::net::UnixStream::connect(path).await {
        Ok(s) => s,
        Err(e) => {
            warn!("varlink root version: failed to connect to {path}: {e}");
            return None;
        }
    };

    let request = serde_json::json!({
        "method": "org.avocado.RootAuthority.Show",
        "parameters": {}
    });
    let mut payload = serde_json::to_vec(&request).ok()?;
    payload.push(0u8);
    if stream.write_all(&payload).await.is_err() {
        return None;
    }
    let _ = stream.shutdown().await;

    let mut buf = Vec::new();
    if stream.read_to_end(&mut buf).await.is_err() {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let resp: serde_json::Value = serde_json::from_slice(&buf[..end]).ok()?;

    resp.get("parameters")
        .and_then(|p| p.get("authority"))
        .and_then(|a| a.get("version"))
        .and_then(|v| v.as_u64())
}

/// Query the active runtime via avocadoctl's varlink List method.
///
/// Returns `Some(RuntimeConfig)` with the active runtime's id/name/version,
/// or `None` if unavailable. Best-effort — failures are logged but don't
/// prevent startup.
pub async fn varlink_get_active_runtime(socket_addr: &str) -> Option<RuntimeConfig> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let path = socket_addr.strip_prefix("unix:").unwrap_or(socket_addr);

    let mut stream = match tokio::net::UnixStream::connect(path).await {
        Ok(s) => s,
        Err(e) => {
            warn!("varlink active runtime: failed to connect to {path}: {e}");
            return None;
        }
    };

    let request = serde_json::json!({
        "method": "org.avocado.Runtimes.List",
        "parameters": {}
    });
    let mut payload = serde_json::to_vec(&request).ok()?;
    payload.push(0u8);
    if stream.write_all(&payload).await.is_err() {
        return None;
    }
    let _ = stream.shutdown().await;

    let mut buf = Vec::new();
    if stream.read_to_end(&mut buf).await.is_err() {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let resp: serde_json::Value = serde_json::from_slice(&buf[..end]).ok()?;

    let runtimes = resp
        .get("parameters")
        .and_then(|p| p.get("runtimes"))
        .and_then(|r| r.as_array())?;

    let active = runtimes
        .iter()
        .find(|rt| rt.get("active").and_then(|a| a.as_bool()).unwrap_or(false))?;

    let id = active.get("id").and_then(|v| v.as_str()).map(String::from);
    let runtime_info = active.get("runtime");
    let name = runtime_info
        .and_then(|r| r.get("name"))
        .and_then(|v| v.as_str())
        .map(String::from);
    let version = runtime_info
        .and_then(|r| r.get("version"))
        .and_then(|v| v.as_str())
        .map(String::from);

    Some(RuntimeConfig { id, name, version })
}

/// Call avocadoctl's varlink AddFromUrl over the Unix socket.
///
/// The varlink wire protocol: send a NUL-terminated JSON request, read a
/// NUL-terminated JSON response.  The socket address uses the `unix:` prefix
/// (e.g. `unix:/run/avocado/avocadoctl.sock`).
async fn varlink_add_from_url(
    socket_addr: &str,
    url: &str,
    auth_token: &str,
    artifacts_url: Option<&str>,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let path = socket_addr.strip_prefix("unix:").unwrap_or(socket_addr);

    let mut stream = tokio::net::UnixStream::connect(path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to connect to avocadoctl socket {path}: {e}"))?;

    let mut params = serde_json::json!({ "url": url, "authToken": auth_token });
    if let Some(art_url) = artifacts_url {
        params["artifactsUrl"] = serde_json::json!(art_url);
    }
    let request = serde_json::json!({
        "method": "org.avocado.Runtimes.AddFromUrl",
        "parameters": params
    });
    let mut payload = serde_json::to_vec(&request)?;
    payload.push(0u8); // varlink message delimiter
    stream.write_all(&payload).await?;
    stream.shutdown().await?;

    // Read response (NUL-terminated)
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let resp: serde_json::Value = serde_json::from_slice(&buf[..end])
        .map_err(|e| anyhow::anyhow!("invalid varlink response: {e}"))?;

    if let Some(err) = resp.get("error") {
        let reason = resp["parameters"]["reason"]
            .as_str()
            .unwrap_or("unknown error");
        anyhow::bail!("{}: {}", err.as_str().unwrap_or("error"), reason);
    }

    Ok(())
}

/// Call rat over Unix socket, return the response JSON.
/// Send one request to `rat`, giving up after `rat_timeout_secs`.
async fn rat_call(cfg: &TunnelConfig, request: &serde_json::Value) -> Result<serde_json::Value> {
    let limit = Duration::from_secs(cfg.rat_timeout_secs);
    tokio::time::timeout(limit, rat_exchange(&cfg.rat_socket_path, request))
        .await
        .map_err(|_| anyhow::anyhow!("rat did not answer within {limit:?}"))?
}

async fn rat_exchange(socket_path: &str, request: &serde_json::Value) -> Result<serde_json::Value> {
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
    let lo = cfg.wg_port_lo.unwrap_or(DEVICE_PORT_LO);
    let hi = cfg.wg_port_hi.unwrap_or(DEVICE_PORT_HI);
    let req = serde_json::json!({
        "command": "find_port",
        "lo": lo,
        "hi": hi,
    });
    let resp = rat_call(cfg, &req).await?;
    let listen_port = resp["data"]["port"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("rat find_port returned no port"))?
        as u16;

    let private_key = generate_wg_private_key();

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

fn generate_wg_private_key() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn derive_public_key(private_key: &str) -> Result<String> {
    use base64::Engine;
    use x25519_dalek::{PublicKey, StaticSecret};
    let bytes = base64::engine::general_purpose::STANDARD.decode(private_key.trim())?;
    let secret: StaticSecret = StaticSecret::from(
        <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("private key must be 32 bytes"))?,
    );
    let public: PublicKey = PublicKey::from(&secret);
    Ok(base64::engine::general_purpose::STANDARD.encode(public.as_bytes()))
}

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

fn parse_expiry_unix(expires_at: &str) -> u64 {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(expires_at) {
        return dt.timestamp().max(0) as u64;
    }
    unix_now_secs() + 3600
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_hung_rat_times_out() {
        let dir = std::env::temp_dir().join(format!("conn-rat-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let sock = dir.join("rat.sock");
        let _ = std::fs::remove_file(&sock);
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        // Accept and hold the connection without ever answering.
        let _hold = tokio::spawn(async move {
            let (_conn, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await
        });
        let cfg = TunnelConfig {
            rat_socket_path: sock.to_string_lossy().into(),
            rat_timeout_secs: 1,
            ..Default::default()
        };
        let err = rat_call(&cfg, &serde_json::json!({"op": "x"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("did not answer"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    async fn handle(text: &str, lh: Option<&tokio::sync::mpsc::Sender<String>>) -> Vec<String> {
        let (out_tx, _out_rx) = tokio::sync::mpsc::unbounded_channel();
        handle_server_message(
            text,
            &mut HashMap::new(),
            &crate::config::TunnelConfig::default(),
            &Arc::new(Mutex::new(HashMap::new())),
            &Arc::new(AtomicBool::new(false)),
            "",
            "",
            None,
            None,
            &None,
            "/nonexistent.sock",
            &out_tx,
            30,
            lh,
        )
        .await
    }

    #[tokio::test]
    async fn unknown_types_go_to_the_local_handler_only_when_configured() {
        let msg = r#"{"type":"something_else","id":"1"}"#;
        // Unconfigured: ignored exactly as before the local handler existed.
        assert!(handle(msg, None).await.is_empty());

        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        assert!(handle(msg, Some(&tx)).await.is_empty());
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&rx.try_recv().unwrap()).unwrap(),
            serde_json::from_str::<serde_json::Value>(msg).unwrap()
        );
        // Untyped messages are never forwarded.
        assert!(handle(r#"{"id":"2"}"#, Some(&tx)).await.is_empty());
        assert!(rx.try_recv().is_err());
        // Pretty-printed JSON still reaches the handler as one line.
        handle("{\n  \"type\": \"x\",\n  \"id\": \"3\"\n}", Some(&tx)).await;
        let fwd = rx.try_recv().unwrap();
        assert!(!fwd.contains('\n'));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&fwd).unwrap()["id"],
            "3"
        );
    }

    #[tokio::test]
    async fn a_repeated_tunnel_request_gets_the_same_answer() {
        // rat is unreachable, so preparing again would nack: a repeat must be
        // answered from the pending entry, with the same key and port.
        let cfg = crate::config::TunnelConfig {
            rat_socket_path: "/nonexistent/rat.sock".into(),
            rat_timeout_secs: 1,
            ..Default::default()
        };
        let key = generate_wg_private_key();
        let mut pending = HashMap::new();
        pending.insert(
            "t1".to_string(),
            TunnelPrep {
                private_key: key.clone(),
                listen_port: 51000,
                iface_name: "avot1".into(),
                expires_at: "2030-01-01T00:00:00Z".into(),
                tunnel_prn: String::new(),
            },
        );
        let (out_tx, _out_rx) = tokio::sync::mpsc::unbounded_channel();
        let replies = handle_server_message(
            r#"{"type":"tunnel_request","tunnel_id":"t1","expires_at":"2030-01-01T00:00:00Z"}"#,
            &mut pending,
            &cfg,
            &Arc::new(Mutex::new(HashMap::new())),
            &Arc::new(AtomicBool::new(true)),
            "",
            "",
            None,
            None,
            &None,
            "/nonexistent.sock",
            &out_tx,
            30,
            None,
        )
        .await;
        assert_eq!(replies.len(), 2, "{replies:?}");
        let configure: serde_json::Value = serde_json::from_str(&replies[1]).unwrap();
        assert_eq!(configure["type"], "tunnel_configure");
        assert_eq!(configure["device_endpoint_port"], 51000);
        assert_eq!(
            configure["device_public_key"],
            derive_public_key(&key).unwrap()
        );
        assert!(pending.contains_key("t1"));
    }

    #[tokio::test]
    async fn a_tunnel_that_cannot_be_prepared_is_nacked() {
        // rat answered the probe, but the request itself fails (here: no socket).
        let cfg = crate::config::TunnelConfig {
            rat_socket_path: "/nonexistent/rat.sock".into(),
            rat_timeout_secs: 1,
            ..Default::default()
        };
        let (out_tx, _out_rx) = tokio::sync::mpsc::unbounded_channel();
        let replies = handle_server_message(
            r#"{"type":"tunnel_request","tunnel_id":"t1","expires_at":"2030-01-01T00:00:00Z"}"#,
            &mut HashMap::new(),
            &cfg,
            &Arc::new(Mutex::new(HashMap::new())),
            &Arc::new(AtomicBool::new(true)),
            "",
            "",
            None,
            None,
            &None,
            "/nonexistent.sock",
            &out_tx,
            30,
            None,
        )
        .await;
        assert_eq!(replies.len(), 1);
        let nack: serde_json::Value = serde_json::from_str(&replies[0]).unwrap();
        assert_eq!(nack["type"], "tunnel_nack");
        assert_eq!(nack["tunnel_id"], "t1");
        assert!(
            nack["reason"]
                .as_str()
                .unwrap()
                .starts_with("prepare_failed")
        );
    }

    #[test]
    fn eventloop_forwards_only_what_the_loop_acts_on() {
        use rumqttc::{ConnAck, ConnectReturnCode, Outgoing, PubAck, Publish};
        let ack = ConnAck {
            session_present: false,
            code: ConnectReturnCode::Success,
        };
        assert!(forwarded(&Ok(Event::Incoming(Packet::ConnAck(ack)))));
        let p = Publish::new("cmd/x", QoS::AtLeastOnce, "{}");
        assert!(forwarded(&Ok(Event::Incoming(Packet::Publish(p)))));
        assert!(forwarded(&Ok(Event::Incoming(Packet::Disconnect))));
        assert!(forwarded(&Err(rumqttc::ConnectionError::RequestsDone)));
        // The per-publish chatter that used to fill the channel is dropped.
        assert!(!forwarded(&Ok(Event::Outgoing(Outgoing::Publish(1)))));
        assert!(!forwarded(&Ok(Event::Incoming(Packet::PubAck(
            PubAck::new(1)
        )))));
        assert!(!forwarded(&Ok(Event::Incoming(Packet::PingResp))));
    }

    fn gate() -> &'static UpdateGate {
        Box::leak(Box::new(UpdateGate::new()))
    }

    #[test]
    fn update_slot_admits_one_holder_and_survives_a_panic() {
        let gate = gate();
        let first = gate.claim();
        assert!(first.is_some(), "first nudge should take the slot");
        // Rejected claims must not release the held slot.
        assert!(gate.claim().is_none());
        assert!(gate.claim().is_none());
        drop(first);
        assert!(gate.claim().is_some(), "reusable once the update finishes");

        let panicked = std::panic::catch_unwind(|| {
            let _slot = gate.claim().expect("slot should be free");
            panic!("update blew up");
        });
        assert!(panicked.is_err());
        assert!(gate.claim().is_some(), "a panic must not leak the slot");
    }

    #[tokio::test]
    async fn a_nudge_during_an_update_runs_one_more_pass() {
        let gate = gate();
        let passes = std::cell::Cell::new(0);
        let slot = gate.nudge().unwrap();
        gate.drain(slot, || {
            passes.set(passes.get() + 1);
            if passes.get() == 1 {
                // Two nudges mid-pass: both queue, together buying one pass.
                assert!(gate.nudge().is_none());
                assert!(gate.nudge().is_none());
            }
            async {}
        })
        .await;
        assert_eq!(passes.get(), 2);
        assert!(gate.claim().is_some(), "slot released after draining");
    }

    #[test]
    fn parse_expiry_unix_returns_correct_timestamp() {
        let ts = parse_expiry_unix("2030-01-01T00:00:00Z");
        assert_eq!(ts, 1_893_456_000);
    }

    #[test]
    fn parse_expiry_unix_handles_offset_timestamps() {
        let ts = parse_expiry_unix("2030-01-01T01:00:00+01:00");
        assert_eq!(ts, 1_893_456_000);
    }

    #[test]
    fn parse_expiry_unix_falls_back_on_invalid_input() {
        let before = unix_now_secs();
        let ts = parse_expiry_unix("not-a-date");
        let after = unix_now_secs();
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
        let ts = parse_expiry_unix("1970-01-01T00:00:00Z");
        assert_eq!(ts, 0);
    }

    #[test]
    fn remaining_ttl_secs_returns_fallback_for_invalid_input() {
        assert_eq!(remaining_ttl_secs("bad-date"), 3600);
    }

    #[test]
    fn remaining_ttl_secs_returns_fallback_for_expired_timestamp() {
        assert_eq!(remaining_ttl_secs("2020-01-01T00:00:00Z"), 3600);
    }

    #[test]
    fn remaining_ttl_secs_returns_seconds_for_future_timestamp() {
        let two_hours = unix_now_secs() + 7200;
        let ts_str = chrono::DateTime::from_timestamp(two_hours as i64, 0)
            .unwrap()
            .to_rfc3339();
        let secs = remaining_ttl_secs(&ts_str);
        assert!(secs > 7190 && secs <= 7200, "expected ~7200, got {secs}");
    }

    #[test]
    fn tunnel_close_msg_uses_tunnel_id_key() {
        // The server route matches `%{"type" => "tunnel_close", "tunnel_id" => id}`
        // and uses the value for `Relay.get_tunnel(id)`. A message keyed on
        // `tunnel_prn` falls through to the catch-all and the tunnel is never
        // closed server-side. Every other tunnel_* event keys on `tunnel_id`.
        let msg: serde_json::Value =
            serde_json::from_str(&tunnel_close_msg("tunnel-abc123")).unwrap();
        assert_eq!(msg["type"], "tunnel_close");
        assert_eq!(msg["tunnel_id"], "tunnel-abc123");
        assert!(
            msg.get("tunnel_prn").is_none(),
            "server does not read tunnel_prn; it must not be the lookup key"
        );
    }
}
