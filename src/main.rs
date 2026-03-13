use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::info;

mod agent;
mod claim;
mod config;
mod device_id;
mod mqtt;

use config::AgentConfig;

#[derive(Parser)]
#[command(name = "avocado-conn", about = "Avocado Connect device daemon")]
struct Cli {
    /// Path to config file
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the daemon (connect to MQTT broker and handle commands)
    Run,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let config_path = match &cli.config {
        Some(p) => p.clone(),
        None => AgentConfig::default_path()?,
    };

    let config = AgentConfig::load(&config_path)?;
    config.validate_claim_config()?;

    match cli.command {
        Commands::Run => run_daemon(config).await?,
    }

    Ok(())
}

async fn run_daemon(config: AgentConfig) -> Result<()> {
    // Phase 1: Resolve credentials — either from saved state, by claiming, or
    // from the static [mqtt] config section.
    let (mqtt_cfg, tuf_url, artifacts_url) = if let Some(state) = config.load_claimed_state()? {
        info!(device_id = %state.device_id, "loaded saved credentials");
        (state.mqtt, state.tuf_url, state.artifacts_url)
    } else if config.needs_claim() {
        info!("no saved credentials, starting claim flow");

        // Run the claim loop as a background task that is cancellable via
        // SIGTERM/SIGINT so systemd can stop the service cleanly.
        let state = tokio::select! {
            result = claim::claim_with_retry(&config) => result?,
            _ = shutdown_signal() => {
                info!("shutdown received during claim flow");
                return Ok(());
            }
        };

        config.save_claimed_state(&state)?;
        info!(device_id = %state.device_id, "claim successful, credentials saved");
        (state.mqtt, state.tuf_url, state.artifacts_url)
    } else {
        let mqtt_cfg = config.resolve_mqtt()?;
        (
            mqtt_cfg,
            config.tuf_url.clone(),
            config.artifacts_url.clone(),
        )
    };

    // Phase 2: Run the MQTT agent with resolved credentials.
    info!(host = %mqtt_cfg.host, port = mqtt_cfg.port, "starting avocado-conn");
    agent::run(
        mqtt_cfg,
        config.intervals,
        config.tunnel,
        config.api_url,
        tuf_url,
        artifacts_url,
        config.runtime,
        config.avocadoctl_socket,
    )
    .await
}

/// Wait for SIGTERM or SIGINT.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate()).expect("register SIGTERM handler");
        tokio::select! {
            r = tokio::signal::ctrl_c() => { r.expect("register SIGINT handler"); }
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("register SIGINT handler");
    }
}
