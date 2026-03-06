use anyhow::Result;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::time::Duration;
use tracing::{info, warn};

use crate::config::{IntervalConfig, MqttConfig, RuntimeConfig, TunnelConfig};
use crate::mqtt;

async fn probe_rat(socket_path: &str) -> bool {
    tokio::net::UnixStream::connect(socket_path).await.is_ok()
}

pub async fn run(
    mqtt_cfg: MqttConfig,
    intervals: IntervalConfig,
    tunnel_config: TunnelConfig,
    api_url: String,
    tuf_url: Option<String>,
    artifacts_url: Option<String>,
    runtime: Option<RuntimeConfig>,
) -> Result<()> {
    let rat_available = probe_rat(&tunnel_config.rat_socket_path).await;
    info!(rat_available, "rat probe complete");

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

    // MQTT connect loop with auto-reconnect.
    let mqtt_handle = tokio::spawn({
        let tunnels = active_tunnels.clone();
        let mut shutdown_rx = shutdown_rx;
        async move {
            loop {
                match mqtt::connect_and_run(
                    &mqtt_cfg,
                    intervals.keepalive_secs,
                    tunnel_config.clone(),
                    tunnels.clone(),
                    &mut outbox_rx,
                    &mut shutdown_rx,
                    rat_available,
                    &api_url,
                    tuf_url.as_deref(),
                    artifacts_url.as_deref(),
                    runtime.clone(),
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
