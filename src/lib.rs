use std::env;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use arti_client::{BootstrapBehavior, StreamPrefs, TorClient, TorClientConfig, config::TorClientConfigBuilder};
use bb8::{ManageConnection, Pool};
use fast_socks5::ReplyError;
use fast_socks5::Socks5Command;
use fast_socks5::server::Socks5ServerProtocol;
use fast_socks5::server::states;
use fast_socks5::util::target_addr::TargetAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tor_rtcompat::PreferredRuntime;
use tracing::{error, info, warn};

pub trait AsyncIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AsyncIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

type BoxedIo = Box<dyn AsyncIo>;

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub listen_addr: SocketAddr,
    pub pool_size: u32,
    pub request_timeout: Duration,
    pub new_circuit_period: Duration,
    pub max_circuit_dirtiness: Duration,
    pub circuit_build_timeout: Duration,
    pub optimistic_streams: bool,
    pub state_dir: Option<PathBuf>,
    pub cache_dir: Option<PathBuf>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 9050)),
            pool_size: 8,
            request_timeout: Duration::from_secs(30),
            new_circuit_period: Duration::from_secs(120),
            max_circuit_dirtiness: Duration::from_secs(600),
            circuit_build_timeout: Duration::from_secs(60),
            optimistic_streams: true,
            state_dir: None,
            cache_dir: None,
        }
    }
}

impl ProxyConfig {
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|key| env::var(key).ok())
    }

    fn from_lookup<F>(lookup: F) -> Result<Self>
    where
        F: Fn(&str) -> Option<String>,
    {
        let mut config = Self::default();

        if let Some(value) = lookup("ARTI_PROXY_LISTEN_ADDR") {
            config.listen_addr = value
                .parse()
                .with_context(|| format!("invalid ARTI_PROXY_LISTEN_ADDR: {value}"))?;
        }

        if let Some(value) = lookup("ARTI_PROXY_POOL_SIZE") {
            config.pool_size = value
                .parse()
                .with_context(|| format!("invalid ARTI_PROXY_POOL_SIZE: {value}"))?;
        }

        if let Some(value) = lookup("ARTI_PROXY_REQUEST_TIMEOUT_SECS") {
            config.request_timeout = parse_duration_secs("ARTI_PROXY_REQUEST_TIMEOUT_SECS", &value)?;
        }

        if let Some(value) = lookup("ARTI_PROXY_NEW_CIRCUIT_PERIOD_SECS") {
            config.new_circuit_period =
                parse_duration_secs("ARTI_PROXY_NEW_CIRCUIT_PERIOD_SECS", &value)?;
        }

        if let Some(value) = lookup("ARTI_PROXY_MAX_CIRCUIT_DIRTINESS_SECS") {
            config.max_circuit_dirtiness =
                parse_duration_secs("ARTI_PROXY_MAX_CIRCUIT_DIRTINESS_SECS", &value)?;
        }

        if let Some(value) = lookup("ARTI_PROXY_CIRCUIT_BUILD_TIMEOUT_SECS") {
            config.circuit_build_timeout =
                parse_duration_secs("ARTI_PROXY_CIRCUIT_BUILD_TIMEOUT_SECS", &value)?;
        }

        if let Some(value) = lookup("ARTI_PROXY_OPTIMISTIC_STREAMS") {
            config.optimistic_streams = parse_bool("ARTI_PROXY_OPTIMISTIC_STREAMS", &value)?;
        }

        config.state_dir = lookup("ARTI_PROXY_STATE_DIR").map(PathBuf::from);
        config.cache_dir = lookup("ARTI_PROXY_CACHE_DIR").map(PathBuf::from);

        if config.state_dir.is_some() ^ config.cache_dir.is_some() {
            bail!("ARTI_PROXY_STATE_DIR and ARTI_PROXY_CACHE_DIR must either both be set or both be unset");
        }

        if config.pool_size == 0 {
            bail!("ARTI_PROXY_POOL_SIZE must be greater than zero");
        }

        Ok(config)
    }

    pub fn arti_config(&self) -> Result<TorClientConfig> {
        let mut builder = match (&self.state_dir, &self.cache_dir) {
            (Some(state_dir), Some(cache_dir)) => {
                TorClientConfigBuilder::from_directories(state_dir, cache_dir)
            }
            (None, None) => TorClientConfig::builder(),
            _ => unreachable!("validated in ProxyConfig::from_lookup"),
        };

        // These are the closest Arti equivalents to the C Tor tuning from alpine-tor:
        // shorter preemptive prediction lifetime, bounded circuit dirtiness, and a
        // more aggressive circuit build timeout.
        builder
            .circuit_timing()
            .max_dirtiness(self.max_circuit_dirtiness)
            .request_timeout(self.circuit_build_timeout)
            .request_loyalty(self.new_circuit_period);
        builder
            .preemptive_circuits()
            .prediction_lifetime(self.new_circuit_period)
            .set_initial_predicted_ports(vec![80, 443]);

        builder
            .build()
            .map_err(|error| anyhow!("failed to build arti client config: {error}"))
    }
}

fn parse_duration_secs(name: &str, value: &str) -> Result<Duration> {
    let seconds = value
        .parse::<u64>()
        .with_context(|| format!("invalid {name}: {value}"))?;
    Ok(Duration::from_secs(seconds))
}

fn parse_bool(name: &str, value: &str) -> Result<bool> {
    match value {
        "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON" => Ok(true),
        "0" | "false" | "FALSE" | "no" | "NO" | "off" | "OFF" => Ok(false),
        _ => bail!("invalid {name}: {value}"),
    }
}

pub trait Connector: Send + Sync + 'static {
    fn connect(
        &self,
        target: TargetAddr,
    ) -> Pin<Box<dyn Future<Output = Result<BoxedIo>> + Send + 'static>>;
}

#[derive(Clone)]
struct ArtiClientManager {
    base_client: Arc<TorClient<PreferredRuntime>>,
}

impl ManageConnection for ArtiClientManager {
    type Connection = Arc<TorClient<PreferredRuntime>>;
    type Error = anyhow::Error;

    fn connect(&self) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
        let client = self.base_client.isolated_client();
        async move { Ok(client) }
    }

    fn is_valid(
        &self,
        _conn: &mut Self::Connection,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        std::future::ready(Ok(()))
    }

    fn has_broken(&self, _conn: &mut Self::Connection) -> bool {
        false
    }
}

#[derive(Clone)]
pub struct ArtiConnector {
    pool: Pool<ArtiClientManager>,
    optimistic_streams: bool,
}

impl ArtiConnector {
    pub async fn new(config: &ProxyConfig) -> Result<Self> {
        let base_client = TorClient::builder()
            .config(config.arti_config()?)
            .bootstrap_behavior(BootstrapBehavior::Manual)
            .create_bootstrapped()
            .await
            .context("failed to bootstrap arti client")?;

        let manager = ArtiClientManager { base_client };
        let pool = Pool::builder()
            .max_size(config.pool_size)
            .min_idle(Some(config.pool_size))
            .build(manager)
            .await
            .context("failed to build arti client pool")?;

        Ok(Self {
            pool,
            optimistic_streams: config.optimistic_streams,
        })
    }

    fn stream_prefs(&self) -> StreamPrefs {
        let mut prefs = StreamPrefs::new();
        if self.optimistic_streams {
            prefs.optimistic();
        }
        prefs.new_isolation_group();
        prefs
    }
}

impl Connector for ArtiConnector {
    fn connect(
        &self,
        target: TargetAddr,
    ) -> Pin<Box<dyn Future<Output = Result<BoxedIo>> + Send + 'static>> {
        let pool = self.pool.clone();
        let prefs = self.stream_prefs();
        Box::pin(async move {
            let client = pool
                .get()
                .await
                .map_err(|error| anyhow!("failed to acquire arti client: {error:?}"))?;
            let (host, port) = target.into_string_and_port();
            let stream = client
                .connect_with_prefs((host.as_str(), port), &prefs)
                .await
                .with_context(|| format!("failed to connect to {host}:{port} over arti"))?;
            Ok(Box::new(stream) as BoxedIo)
        })
    }
}

pub struct RotatingProxy<C> {
    listen_addr: SocketAddr,
    request_timeout: Duration,
    connector: Arc<C>,
}

impl RotatingProxy<ArtiConnector> {
    pub async fn from_config(config: ProxyConfig) -> Result<Self> {
        let connector = ArtiConnector::new(&config).await?;
        Ok(Self {
            listen_addr: config.listen_addr,
            request_timeout: config.request_timeout,
            connector: Arc::new(connector),
        })
    }
}

impl<C> RotatingProxy<C>
where
    C: Connector,
{
    pub fn new(listen_addr: SocketAddr, request_timeout: Duration, connector: C) -> Self {
        Self {
            listen_addr,
            request_timeout,
            connector: Arc::new(connector),
        }
    }

    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(self.listen_addr)
            .await
            .with_context(|| format!("failed to bind {}", self.listen_addr))?;

        info!(
            listen_addr = %listener.local_addr()?,
            timeout_secs = self.request_timeout.as_secs(),
            "rotating SOCKS5 proxy is listening"
        );

        loop {
            let (socket, peer_addr) = listener.accept().await.context("accept failed")?;
            let connector = Arc::clone(&self.connector);
            let request_timeout = self.request_timeout;

            tokio::spawn(async move {
                match tokio::time::timeout(
                    request_timeout,
                    handle_socks_connection(socket, connector),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => error!(%peer_addr, "{error:#}"),
                    Err(error) => warn!(%peer_addr, "request timed out: {error}"),
                }
            });
        }
    }
}

async fn handle_socks_connection<C>(socket: TcpStream, connector: Arc<C>) -> Result<()>
where
    C: Connector,
{
    let (proto, command, target_addr) = Socks5ServerProtocol::accept_no_auth(socket)
        .await
        .context("SOCKS handshake failed")?
        .read_command()
        .await
        .context("failed to read SOCKS command")?;

    match command {
        Socks5Command::TCPConnect => handle_tcp_connect(proto, target_addr, connector).await,
        other => {
            proto.reply_error(&ReplyError::CommandNotSupported)
                .await
                .context("failed to send unsupported command reply")?;
            bail!("unsupported SOCKS command: {other:?}");
        }
    }
}

async fn handle_tcp_connect<C>(
    proto: Socks5ServerProtocol<TcpStream, states::CommandRead>,
    target_addr: TargetAddr,
    connector: Arc<C>,
) -> Result<()>
where
    C: Connector,
{
    let target_display = target_addr.to_string();
    let mut outbound = match connector.connect(target_addr).await {
        Ok(stream) => stream,
        Err(error) => {
            proto.reply_error(&ReplyError::HostUnreachable)
                .await
                .context("failed to send connect error reply")?;
            return Err(error);
        }
    };

    let mut inbound = proto
        .reply_success(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .context("failed to send connect success reply")?;

    match tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await {
        Ok(_) => {}
        Err(error) => {
            let error = anyhow::Error::from(error);
            if is_benign_disconnect(&error) {
                return Ok(());
            }
            return Err(error)
                .with_context(|| format!("failed while proxying {target_display}"));
        }
    }

    Ok(())
}

/// Arti reports `NotConnected` when a Tor stream is shut down after EOF instead of
/// returning a clean I/O EOF, so `copy_bidirectional` can fail during normal teardown.
fn is_benign_disconnect(error: &anyhow::Error) -> bool {
    error.chain().any(is_benign_disconnect_source)
}

fn is_benign_disconnect_source(error: &(dyn std::error::Error + 'static)) -> bool {
    if let Some(io_error) = error.downcast_ref::<std::io::Error>() {
        return matches!(
            io_error.kind(),
            std::io::ErrorKind::NotConnected
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::UnexpectedEof
        );
    }

    error.to_string() == "Stream not connected"
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::sync::Mutex;

    use fast_socks5::client::Config as ClientConfig;
    use fast_socks5::client::Socks5Stream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn benign_disconnect_recognizes_expected_teardown_errors() {
        assert!(is_benign_disconnect(&anyhow::Error::from(
            std::io::Error::new(std::io::ErrorKind::NotConnected, "Stream not connected")
        )));
        assert!(is_benign_disconnect(&anyhow::anyhow!("Stream not connected")));
        assert!(is_benign_disconnect(&anyhow::Error::from(
            std::io::Error::from(std::io::ErrorKind::BrokenPipe)
        )));
        assert!(!is_benign_disconnect(&anyhow::anyhow!(
            "Received an END cell with reason EXITPOLICY"
        )));
    }

    #[test]
    fn config_reads_env_overrides() {
        let env = HashMap::from([
            ("ARTI_PROXY_LISTEN_ADDR".to_owned(), "127.0.0.1:1337".to_owned()),
            ("ARTI_PROXY_POOL_SIZE".to_owned(), "16".to_owned()),
            (
                "ARTI_PROXY_NEW_CIRCUIT_PERIOD_SECS".to_owned(),
                "45".to_owned(),
            ),
            (
                "ARTI_PROXY_MAX_CIRCUIT_DIRTINESS_SECS".to_owned(),
                "90".to_owned(),
            ),
            (
                "ARTI_PROXY_CIRCUIT_BUILD_TIMEOUT_SECS".to_owned(),
                "15".to_owned(),
            ),
            ("ARTI_PROXY_OPTIMISTIC_STREAMS".to_owned(), "false".to_owned()),
            ("ARTI_PROXY_STATE_DIR".to_owned(), "/tmp/arti-state".to_owned()),
            ("ARTI_PROXY_CACHE_DIR".to_owned(), "/tmp/arti-cache".to_owned()),
        ]);

        let config = ProxyConfig::from_lookup(|key| env.get(key).cloned()).unwrap();

        assert_eq!(config.listen_addr, "127.0.0.1:1337".parse().unwrap());
        assert_eq!(config.pool_size, 16);
        assert_eq!(config.new_circuit_period, Duration::from_secs(45));
        assert_eq!(config.max_circuit_dirtiness, Duration::from_secs(90));
        assert_eq!(config.circuit_build_timeout, Duration::from_secs(15));
        assert!(!config.optimistic_streams);
        assert_eq!(config.state_dir, Some(PathBuf::from("/tmp/arti-state")));
        assert_eq!(config.cache_dir, Some(PathBuf::from("/tmp/arti-cache")));
    }

    #[tokio::test]
    async fn socks_proxy_forwards_tcp_and_preserves_domain_targets() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = echo_listener.accept().await else {
                    break;
                };

                tokio::spawn(async move {
                    let mut buf = [0_u8; 1024];
                    loop {
                        let read = match socket.read(&mut buf).await {
                            Ok(0) => return,
                            Ok(read) => read,
                            Err(_) => return,
                        };

                        if socket.write_all(&buf[..read]).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });

        let connector = RecordingConnector::new(echo_addr);
        let seen_targets = Arc::clone(&connector.seen_targets);

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let proxy_connector = Arc::new(connector);
        let proxy_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (socket, _) = proxy_listener.accept().await.unwrap();
                handle_socks_connection(socket, Arc::clone(&proxy_connector))
                    .await
                    .unwrap();
            }
        });

        let mut stream = Socks5Stream::connect(
            proxy_addr,
            "example.com".to_owned(),
            80,
            ClientConfig::default(),
        )
        .await
        .unwrap();
        stream.write_all(b"hello over socks").await.unwrap();
        let mut buf = vec![0_u8; "hello over socks".len()];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, b"hello over socks");
        drop(stream);

        let mut stream = Socks5Stream::connect(
            proxy_addr,
            "example.net".to_owned(),
            443,
            ClientConfig::default(),
        )
        .await
        .unwrap();
        stream.write_all(b"second request").await.unwrap();
        let mut buf = vec![0_u8; "second request".len()];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, b"second request");
        drop(stream);

        proxy_task.await.unwrap();
        echo_task.abort();

        let recorded = seen_targets.lock().unwrap().clone();
        assert_eq!(
            recorded,
            vec!["example.com:80".to_owned(), "example.net:443".to_owned()]
        );
    }

    #[derive(Clone)]
    struct RecordingConnector {
        upstream_addr: SocketAddr,
        seen_targets: Arc<Mutex<Vec<String>>>,
    }

    impl RecordingConnector {
        fn new(upstream_addr: SocketAddr) -> Self {
            Self {
                upstream_addr,
                seen_targets: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl Connector for RecordingConnector {
        fn connect(
            &self,
            target: TargetAddr,
        ) -> Pin<Box<dyn Future<Output = Result<BoxedIo>> + Send + 'static>> {
            let upstream_addr = self.upstream_addr;
            let seen_targets = Arc::clone(&self.seen_targets);

            Box::pin(async move {
                seen_targets.lock().unwrap().push(target.to_string());
                let stream = TcpStream::connect(upstream_addr)
                    .await
                    .context("failed to connect test upstream")?;
                Ok(Box::new(stream) as BoxedIo)
            })
        }
    }
}
