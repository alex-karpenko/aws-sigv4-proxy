use aws_sigv4_proxy::{config::Config, credentials::CachedCredentials, proxy, signals, utils};
use clap::Parser;
use tokio::{select, sync::watch};
use tracing::{debug, error, info};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cfg = Config::parse();
    debug!(?cfg, "without aws config applied");

    let aws_config = cfg.load_default_aws_config().await?;
    let cfg = cfg.apply_aws_config(&aws_config).await?;
    let credentials_provider = CachedCredentials::new(&aws_config, &cfg.assume_role, cfg.signature_lifetime).await?;
    debug!(?cfg, "with aws config");

    info!(service = ?cfg.service, region = ?cfg.region, forward_to = %cfg.forward_to, "Current configuration");

    let (shutdown_tx, _) = watch::channel(false);
    let mut signal_waiter = signals::SignalHandler::new()?;
    let proxy_listener = proxy::listener(&cfg, credentials_provider, shutdown_tx.subscribe()).await?;
    let utility_listener = utils::listener(&cfg, shutdown_tx.subscribe()).await?;

    select! {
        biased;
        _ = signal_waiter.wait_for_signal() => {
            info!("Shutting down...");
            shutdown_tx.send(true)?;
        }
        res = proxy_listener => {
            let _ = shutdown_tx.send(true);
            error!(error = ?res?, "Proxy listener exited unexpectedly");
        }
        res = utility_listener => {
            let _ = shutdown_tx.send(true);
            error!(error = ?res?, "Utility listener exited unexpectedly");
        }
    }

    info!("Waiting for all requests to be finished");
    shutdown_tx.closed().await;
    info!("Shutdown complete");

    Ok(())
}
