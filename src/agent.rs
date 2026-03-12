use anyhow::Result;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::time::Duration;
use tracing::{info, warn};

use crate::config::{IntervalConfig, MqttConfig, RuntimeConfig, TunnelConfig};
use crate::mqtt;

async fn probe_rat(socket_path: &str) -> bool {
    tokio::net::UnixStream::connect(socket_path).await.is_ok()
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    mqtt_cfg: MqttConfig,
    intervals: IntervalConfig,
    tunnel_config: TunnelConfig,
    api_url: String,
    tuf_url: Option<String>,
    artifacts_url: Option<String>,
    runtime: Option<RuntimeConfig>,
    avocadoctl_socket: String,
) -> Result<()> {
    let initial = probe_rat(&tunnel_config.rat_socket_path).await;
    let rat_available = Arc::new(AtomicBool::new(initial));
    info!(rat_available = initial, "rat probe complete");

    // Shared active-tunnel map: tunnel_id -> (expiry_unix_secs, tunnel_prn).
    // Created once and shared across all reconnects so the watchdog continues
    // to guard tunnels even while the MQTT connection is down.
    let active_tunnels: mqtt::ActiveTunnels = Arc::new(Mutex::new(HashMap::new()));

    // Channel for the expiry watchdog to queue outbound MQTT messages
    // (e.g. tunnel_close notifications) to be sent by the MQTT loop.
    let (outbox_tx, mut outbox_rx) = tokio::sync::mpsc::unbounded_channel::<String>();

    // Shutdown signal: agent sends `true` after closing all tunnels, MQTT loop
    // drains remaining outbox messages and exits cleanly.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let rat_socket_path = tunnel_config.rat_socket_path.clone();

    // Expiry watchdog — independent of MQTT connection state.
    {
        let tunnels = active_tunnels.clone();
        let socket_path = rat_socket_path.clone();
        let tx = outbox_tx.clone();
        tokio::spawn(async move {
            mqtt::expiry_watchdog(tunnels, socket_path, tx).await;
        });
    }

    // Rat availability watchdog — re-probes the rat socket every 30s and
    // publishes an updated shadow if the value changes. This handles both
    // boot races (rat starts after conn) and runtime restarts of rat.
    {
        let rat = rat_available.clone();
        let socket_path = rat_socket_path.clone();
        let tx = outbox_tx.clone();
        let keepalive = intervals.keepalive_secs;
        let avocadoctl = avocadoctl_socket.clone();
        let rt_cfg = runtime.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                let now_available = probe_rat(&socket_path).await;
                let was_available = rat.load(Ordering::Relaxed);
                if now_available != was_available {
                    info!(
                        was = was_available,
                        now = now_available,
                        "rat availability changed"
                    );
                    rat.store(now_available, Ordering::Relaxed);
                    // Publish updated shadow so the server knows immediately.
                    let mut shadow = serde_json::json!({
                        "type": "shadow",
                        "tunnels": now_available,
                        "keepalive_secs": keepalive,
                    });
                    if let Some(v) = mqtt::varlink_get_root_version(&avocadoctl).await {
                        shadow["root_version"] = serde_json::json!(v);
                    }
                    if let Some(rt) = mqtt::varlink_get_active_runtime(&avocadoctl).await {
                        shadow["runtime_id"] = serde_json::json!(rt.id);
                        shadow["runtime_name"] = serde_json::json!(rt.name);
                        shadow["runtime_version"] = serde_json::json!(rt.version);
                    } else if let Some(ref rt) = rt_cfg {
                        shadow["runtime_id"] = serde_json::json!(rt.id);
                        shadow["runtime_name"] = serde_json::json!(rt.name);
                        shadow["runtime_version"] = serde_json::json!(rt.version);
                    }
                    let _ = tx.send(shadow.to_string());
                }
            }
        });
    }

    // MQTT connect loop with auto-reconnect.
    let mqtt_handle = tokio::spawn({
        let tunnels = active_tunnels.clone();
        let mut shutdown_rx = shutdown_rx;
        let outbox_tx_loop = outbox_tx.clone();
        async move {
            loop {
                match mqtt::connect_and_run(
                    &mqtt_cfg,
                    intervals.keepalive_secs,
                    tunnel_config.clone(),
                    tunnels.clone(),
                    &mut outbox_rx,
                    &outbox_tx_loop,
                    &mut shutdown_rx,
                    rat_available.clone(),
                    &api_url,
                    tuf_url.as_deref(),
                    artifacts_url.as_deref(),
                    runtime.clone(),
                    &avocadoctl_socket,
                )
                .await
                {
                    Ok(()) => {
                        info!("MQTT connection closed cleanly");
                    }
                    Err(e) => {
                        warn!("MQTT disconnected: {e}");
                    }
                }

                if *shutdown_rx.borrow() {
                    info!("shutdown signaled — not reconnecting");
                    break;
                }

                info!("reconnecting in 5s...");
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                    _ = shutdown_rx.changed() => {
                        info!("shutdown signaled during reconnect delay — exiting");
                        break;
                    }
                }
            }
        }
    });

    // Wait for SIGTERM or SIGINT.
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate())?;
        tokio::select! {
            r = tokio::signal::ctrl_c() => { r?; info!("received SIGINT"); }
            _ = sigterm.recv() => { info!("received SIGTERM"); }
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        info!("received SIGINT");
    }

    info!("shutting down — closing active tunnels");

    mqtt::shutdown_tunnels(&active_tunnels, &rat_socket_path, &outbox_tx).await;

    let _ = shutdown_tx.send(true);

    match tokio::time::timeout(Duration::from_secs(10), mqtt_handle).await {
        Ok(Ok(())) => info!("MQTT loop exited cleanly"),
        Ok(Err(e)) => warn!("MQTT loop task failed: {e}"),
        Err(_) => warn!("MQTT loop did not exit within 10s, forcing shutdown"),
    }

    Ok(())
}
