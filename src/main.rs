use anyhow::Result;
use arti_proxy::{ProxyConfig, RotatingProxy};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("arti_proxy=info,arti_proxy=debug"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let config = ProxyConfig::from_env()?;
    let proxy = RotatingProxy::from_config(config).await?;
    proxy.run().await
}
