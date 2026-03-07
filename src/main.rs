use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::info;

mod agent;
mod config;
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

#[tokio::main]
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

    match cli.command {
        Commands::Run => {
            let mqtt_cfg = config.resolve_mqtt()?;
            info!(host = %mqtt_cfg.host, port = mqtt_cfg.port, "starting avocado-conn");
            agent::run(
                mqtt_cfg,
                config.intervals,
                config.tunnel,
                config.api_url,
                config.tuf_url,
                config.artifacts_url,
                config.runtime,
                config.avocadoctl_socket,
            )
            .await?;
        }
    }

    Ok(())
}
