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

#[tokio::main]
async fn main() -> Result<()> {
    // Defense-in-depth: Cargo.toml pins the dep graph so `ring` is the
    // only crypto provider in the tree, and rustls 0.23 auto-picks when
    // there's a single provider. Installing it explicitly here belts the
    // suspenders — if a future transitive change accidentally re-adds a
    // second provider on this same rustls 0.23 crate before CI catches it,
    // the explicit install ensures `ring` stays the default.
    //
    // Caveat: this only configures *this* crate's rustls 0.23 instance.
    // A future side-by-side rustls 0.24 from a transitive bump would have
    // its own provider config independent of this call. That scenario is
    // covered by the duplicate-rustls CI guard, not this install.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install rustls ring crypto provider");

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
        let result = tokio::select! {
            result = claim::claim_with_retry(&config) => result,
            _ = shutdown_signal() => {
                info!("shutdown received during claim flow");
                return Ok(());
            }
        };

        match result {
            Ok(state) => {
                config.save_claimed_state(&state)?;
                info!(device_id = %state.device_id, "claim successful, credentials saved");
                (state.mqtt, state.tuf_url, state.artifacts_url)
            }
            Err(_) => {
                // 409 identifier_taken, invalid/expired token, malformed
                // request, etc. Retrying cannot recover — stay alive and idle
                // until operator intervention (config fix, stale device
                // record cleanup, new token) triggers a process restart.
                // Crash-looping here would mean systemd immediately
                // re-hammering /api/device/claim (ENG-1822). The error
                // itself is logged in claim_with_retry with attempt context.
                info!("claim rejected as terminal; idling until restart");
                shutdown_signal().await;
                return Ok(());
            }
        }
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

#[cfg(test)]
mod tests {
    /// Regression guard for the rustls 0.23 dual-provider panic (PR #12).
    /// Mirrors mqtt.rs's TLS config construction.
    ///
    /// Catches:
    /// - Dep-graph regressions where `rustls::crypto::ring` becomes
    ///   unresolvable (compile error: `ring` feature dropped from rustls).
    /// - Dep-graph regressions where `ClientConfig::builder()` panics
    ///   because a second provider sneaks back into the tree.
    /// - rustls API drift that breaks the build path mqtt.rs depends on.
    ///
    /// Does NOT catch: someone removing the `install_default()` call from
    /// `main()` — `cargo test` runs in its own process, separate from main,
    /// so this test does its own install. With the current dep graph
    /// (single provider), removing the install would still work because
    /// rustls auto-picks when only one provider is registered; the install
    /// is defense-in-depth.
    #[test]
    fn rustls_provider_can_build_client_config() {
        // Install ring for this test process. Returns Err if another test
        // in the same process installed first — ignore; we just need *some*
        // default registered before the builder runs.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let _ = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
    }
}
