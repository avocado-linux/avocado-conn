use anyhow::Result;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::time::Duration;
use tracing::{info, warn};

use crate::config::{IntervalConfig, MqttConfig, RuntimeConfig, TunnelConfig};
use crate::mqtt;

/// Fast re-probes after a missed startup probe; a device without the tunnels
/// extension spends about 10 s on these, then settles into the 30 s cadence.
const FAST_RAT_PROBES: u32 = 5;

/// Delay before the next rat probe: 2 s while fast probes remain, else 30 s.
fn next_rat_probe_delay(fast_left: &mut u32) -> Duration {
    if *fast_left > 0 {
        *fast_left -= 1;
        Duration::from_secs(2)
    } else {
        Duration::from_secs(30)
    }
}

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
    local_handler_socket: Option<String>,
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

    // Optional local handler bridge; None leaves message handling unchanged.
    // Its events get their own bounded queue so a chatty handler can't grow
    // memory or crowd out conn's own events during an MQTT outage. Without a
    // handler the sender is just held, so the queue never yields.
    let (handler_events_tx, mut handler_events_rx) =
        tokio::sync::mpsc::channel::<String>(crate::local_handler::EVENTS);
    let local_handler = local_handler_socket.map(|socket| {
        let (tx, rx) = tokio::sync::mpsc::channel(crate::local_handler::QUEUE);
        tokio::spawn(crate::local_handler::run(
            socket,
            rx,
            handler_events_tx.clone(),
        ));
        tx
    });

    // Expiry watchdog — independent of MQTT connection state.
    {
        let tunnels = active_tunnels.clone();
        let cfg = tunnel_config.clone();
        let tx = outbox_tx.clone();
        tokio::spawn(async move {
            mqtt::expiry_watchdog(tunnels, cfg, tx).await;
        });
    }

    // Rat availability watchdog — re-probes the rat socket every 30s and
    // publishes an updated shadow if the value changes. This handles both
    // boot races (rat starts after conn) and runtime restarts of rat. If the
    // startup probe missed rat, the first few re-probes come fast: after an OTA
    // activation conn can start before rat binds its socket.
    {
        let rat = rat_available.clone();
        let socket_path = rat_socket_path.clone();
        let tx = outbox_tx.clone();
        let keepalive = intervals.keepalive_secs;
        let avocadoctl = avocadoctl_socket.clone();
        let rt_cfg = runtime.clone();
        let mut fast_left = if initial { 0 } else { FAST_RAT_PROBES };
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(next_rat_probe_delay(&mut fast_left)).await;
                let now_available = probe_rat(&socket_path).await;
                if now_available {
                    fast_left = 0;
                }
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
        let tunnel_config = tunnel_config.clone();
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
                    &mut handler_events_rx,
                    &outbox_tx_loop,
                    &mut shutdown_rx,
                    rat_available.clone(),
                    &api_url,
                    tuf_url.as_deref(),
                    artifacts_url.as_deref(),
                    runtime.clone(),
                    &avocadoctl_socket,
                    local_handler.as_ref(),
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

    mqtt::shutdown_tunnels(&active_tunnels, &tunnel_config, &outbox_tx).await;

    let _ = shutdown_tx.send(true);

    match tokio::time::timeout(Duration::from_secs(10), mqtt_handle).await {
        Ok(Ok(())) => info!("MQTT loop exited cleanly"),
        Ok(Err(e)) => warn!("MQTT loop task failed: {e}"),
        Err(_) => warn!("MQTT loop did not exit within 10s, forcing shutdown"),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missed_startup_probe_retries_fast_then_settles() {
        let mut fast_left = FAST_RAT_PROBES;
        let delays: Vec<u64> = (0..7)
            .map(|_| next_rat_probe_delay(&mut fast_left).as_secs())
            .collect();
        assert_eq!(delays, [2, 2, 2, 2, 2, 30, 30]);
        // rat found at startup: straight to the normal cadence.
        assert_eq!(next_rat_probe_delay(&mut 0).as_secs(), 30);
    }
}
