//! A simple DERP server.
//!
//! Based on /tailscale/cmd/derper

use std::{
    borrow::Cow,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use anyhow::{anyhow, bail, Context as _, Result};
use clap::Parser;
use futures::{Future, StreamExt};
use http::response::Builder as ResponseBuilder;
use hyper::{server::conn::Http, Body, Method, Request, Response, StatusCode};
use iroh::hp::{
    derp::{
        self,
        http::{ServerBuilder as DerpServerBuilder, TlsAcceptor, TlsConfig},
    },
    key, stun,
};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, UdpSocket};
use tokio_rustls_acme::{caches::DirCache, AcmeConfig};
use tracing::{debug, debug_span, error, info, trace, warn, Instrument};
use tracing_subscriber::{prelude::*, EnvFilter};

type HyperError = Box<dyn std::error::Error + Send + Sync>;
type HyperResult<T> = std::result::Result<T, HyperError>;

/// A simple DERP server.
#[derive(Parser, Debug, Clone)]
#[clap(version, about, long_about = None)]
struct Cli {
    /// Run in localhost development mode.
    #[clap(long, default_value_t = false)]
    dev: bool,
    /// Server HTTPS listen address.
    #[clap(long, short, default_value = "[::]:443")]
    addr: SocketAddr,
    /// The port on which to serve HTTP. The listener is bound to the same IP (if any) as specified in the -a flag.
    #[clap(long, default_value_t = 80)]
    http_port: u16,
    /// The UDP port on which to serve STUN. The listener is bound to the same IP (if any) as specified in the -a flag.
    #[clap(long, default_value_t = 3478)]
    stun_port: u16,
    /// Config file path
    #[clap(long, short)]
    config_path: PathBuf,
    /// Mode for getting a cert. possible options: manual, letsencrypt
    /// When using manual mode, a certificate will be read from `<hostname>.crt` and a private key from
    /// `<hostname>.key`, with the `<hostname>` being the escaped hostname.
    #[clap(long, value_enum, default_value_t = CertMode::LetsEncrypt)]
    cert_mode: CertMode,
    /// Whether to use the LetsEncrypt production or staging server.
    ///
    /// While in developement, LetsEncrypt prefers you to use the staging server. However, the staging server seems to
    /// only use `ECDSA` keys. In their current set up, you can only get intermediate certificates
    /// for `ECDSA` keys if you are on their "allowlist". The production server uses `RSA` keys,
    /// which allow for issuing intermediate certificates in all normal circumstances.
    /// So, to have valid certificates, we must use the LetsEncrypt production server.
    /// Read more here: <https://letsencrypt.org/certificates/#intermediate-certificates>
    /// Default is true. This flag is ignored if we are not using `cert_mode: CertMode::LetsEncrypt`.
    #[clap(long, default_value_t = true)]
    prod_tls: bool,
    /// The contact email for the tls certificate. Required when running the Derper with TLS
    /// enabled.
    #[clap(long)]
    tls_contact: Option<String>,
    /// Directory to store LetsEncrypt certs or read certificates from, if TLS is used.
    #[clap(long)]
    cert_dir: Option<PathBuf>,
    /// Certificate hostname.
    #[clap(long, default_value = "derp.iroh.network.")]
    hostname: String,
    /// Whether to run a STUN server. It will bind to the same IP (if any) as the --addr flag value.
    #[clap(long, default_value_t = true, action = clap::ArgAction::Set)]
    run_stun: bool,
    /// Whether to run a DERP server. The only reason to set this false is if you're decommissioning a
    /// server but want to keep its bootstrap DNS functionality still running.
    #[clap(long, default_value_t = true, action = clap::ArgAction::Set)]
    run_derp: bool,
    /// If non-empty, path to file containing the mesh pre-shared key file. It should contain some hex string; whitespace is trimmed.
    #[clap(long)]
    mesh_psk_file: Option<PathBuf>,
    /// Optional comma-separated list of hostnames to mesh with; the server's own hostname can be in the list
    #[clap(long)]
    mesh_with: Option<Vec<String>>,
    /// Optional comma-separated list of hostnames to make available at /bootstrap-dns.
    #[clap(long)]
    bootstrap_dns_names: Option<Vec<String>>,
    /// Optional comma-separated list of hostnames to make available at /bootstrap-dns and not publish in the list
    #[clap(long)]
    unpublished_dns_names: Option<Vec<String>>,
    /// Rate limit for accepting new connection. Unlimited if not set.
    #[clap(long)]
    accept_conn_limit: Option<f64>,
    /// Burst limit for accepting new connection. Unlimited if not set.
    #[clap(long)]
    accept_conn_burst: Option<usize>,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
enum CertMode {
    Manual,
    LetsEncrypt,
}

impl CertMode {
    async fn gen_server_config(
        &self,
        hostname: String,
        contact: String,
        is_production: bool,
        dir: PathBuf,
    ) -> Result<(Arc<rustls::ServerConfig>, TlsAcceptor)> {
        let config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth();

        match self {
            CertMode::LetsEncrypt => {
                let mut state = AcmeConfig::new(vec![hostname])
                    .contact([format!("mailto:{contact}")])
                    .cache_option(Some(DirCache::new(dir)))
                    .directory_lets_encrypt(is_production)
                    .state();

                let config = config.with_cert_resolver(state.resolver());
                let acceptor = state.acceptor();

                tokio::spawn(async move {
                    loop {
                        match state.next().await.unwrap() {
                            Ok(ok) => debug!("acme event: {:?}", ok),
                            Err(err) => error!("error: {:?}", err),
                        }
                    }
                });

                Ok((Arc::new(config), TlsAcceptor::LetsEncrypt(acceptor)))
            }
            CertMode::Manual => {
                // load certificates manually
                let keyname = escape_hostname(&hostname);
                let cert_path = dir.join(format!("{keyname}.crt"));
                let key_path = dir.join(format!("{keyname}.key"));

                let (certs, private_key) = tokio::task::spawn_blocking(move || {
                    let certs = load_certs(cert_path)?;
                    let key = load_private_key(key_path)?;
                    anyhow::Ok((certs, key))
                })
                .await??;

                let config = config.with_single_cert(certs, private_key)?;
                let config = Arc::new(config);
                let acceptor = tokio_rustls::TlsAcceptor::from(config.clone());

                Ok((config, TlsAcceptor::Manual(acceptor)))
            }
        }
    }
}

fn escape_hostname(hostname: &str) -> Cow<'_, str> {
    let unsafe_hostname_characters = regex::Regex::new(r"[^a-zA-Z0-9-\.]").unwrap();
    unsafe_hostname_characters.replace_all(hostname, "")
}

fn load_certs(filename: impl AsRef<Path>) -> Result<Vec<rustls::Certificate>> {
    let certfile = std::fs::File::open(filename).context("cannot open certificate file")?;
    let mut reader = std::io::BufReader::new(certfile);

    let certs = rustls_pemfile::certs(&mut reader)?
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect();

    Ok(certs)
}

fn load_private_key(filename: impl AsRef<Path>) -> Result<rustls::PrivateKey> {
    let keyfile = std::fs::File::open(filename.as_ref()).context("cannot open private key file")?;
    let mut reader = std::io::BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader).context("cannot parse private key .pem file")? {
            Some(rustls_pemfile::Item::RSAKey(key)) => return Ok(rustls::PrivateKey(key)),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return Ok(rustls::PrivateKey(key)),
            Some(rustls_pemfile::Item::ECKey(key)) => return Ok(rustls::PrivateKey(key)),
            None => break,
            _ => {}
        }
    }

    bail!(
        "no keys found in {} (encrypted keys not supported)",
        filename.as_ref().display()
    );
}

#[derive(Serialize, Deserialize)]
struct Config {
    private_key: key::node::SecretKey,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            private_key: key::node::SecretKey::generate(),
        }
    }
}

impl Config {
    async fn load(opts: &Cli) -> Result<Self> {
        if opts.dev {
            return Ok(Config::default());
        }
        let config_path = &opts.config_path;

        if config_path.exists() {
            Self::read_from_file(&config_path).await
        } else {
            let config = Config::default();
            config.write_to_file(&config_path).await?;

            Ok(config)
        }
    }

    async fn read_from_file(path: impl AsRef<Path>) -> Result<Self> {
        if !path.as_ref().is_file() {
            bail!("config-path must be a valid toml file");
        }
        let config_ser = tokio::fs::read_to_string(path)
            .await
            .context("unable to read config")?;
        let config = toml::from_str(&config_ser).context("unable to decode config")?;

        Ok(config)
    }

    /// Write the content of this configuration to the provided path.
    async fn write_to_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let p = path
            .as_ref()
            .parent()
            .ok_or_else(|| anyhow!("invalid config file path, no parent"))?;
        // TODO: correct permissions (0777 for dir, 0600 for file)
        tokio::fs::create_dir_all(p)
            .await
            .with_context(|| format!("unable to create config-path dir: {}", p.display()))?;
        let config_ser = toml::to_string(self).context("unable to serialize configuration")?;
        tokio::fs::write(path, config_ser)
            .await
            .context("unable to write config file")?;

        Ok(())
    }
}

const DEV_PORT: u16 = 3340;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .init();

    let mut cli = Cli::parse();

    if cli.dev {
        cli.addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), DEV_PORT);
        info!(%cli.addr, "Running in dev mode.");
    }

    let listen_host = cli.addr.ip();
    let serve_tls = cli.addr.port() == 443 || CertMode::Manual == cli.cert_mode;

    if serve_tls && cli.tls_contact.is_none() {
        bail!("Must supply an email address for the `tls_contact` flag when running the derper with TLS enabled.");
    }

    let (secret_key, mesh_key) = match cli.run_derp {
        true => {
            let cfg = Config::load(&cli).await?;
            let mesh_key = if let Some(file) = cli.mesh_psk_file {
                let raw = tokio::fs::read_to_string(file)
                    .await
                    .context("reading mesh-pks file")?;
                let mut mesh_key = [0u8; 32];
                hex::decode_to_slice(raw.trim(), &mut mesh_key)
                    .context("invalid mesh-pks content")?;
                info!("DERP mesh key configured");
                Some(mesh_key)
            } else {
                None
            };
            (Some(cfg.private_key), mesh_key)
        }
        false => (None, None),
    };

    let stun_task = if cli.run_stun {
        Some(tokio::task::spawn(async move {
            serve_stun(listen_host, cli.stun_port).await
        }))
    } else {
        None
    };

    let headers: Vec<(&str, &str)> = if serve_tls {
        TLS_HEADERS.into()
    } else {
        Vec::new()
    };

    let tls_config = if serve_tls {
        // checked earlier
        let contact = cli.tls_contact.expect("checked earlier");
        let is_production = cli.prod_tls;
        let (config, acceptor) = cli
            .cert_mode
            .gen_server_config(
                cli.hostname.clone(),
                contact,
                is_production,
                cli.cert_dir.unwrap_or_else(|| PathBuf::from(".")),
            )
            .await?;
        Some(TlsConfig { config, acceptor })
    } else {
        None
    };

    let derp_server = DerpServerBuilder::new(cli.addr)
        .secret_key(secret_key)
        .mesh_key(mesh_key)
        .headers(headers)
        .tls_config(tls_config)
        .derp_override(Box::new(derp_disabled_handler))
        .request_handler(Method::GET, "/", Box::new(root_handler))
        .request_handler(Method::GET, "/index.html", Box::new(root_handler))
        .request_handler(Method::GET, "/derp/probe", Box::new(probe_handler))
        .request_handler(Method::GET, "/robots.txt", Box::new(robots_handler))
        .spawn()
        .await?;

    let http_addr = SocketAddr::new(cli.addr.ip(), cli.http_port);
    let http_task = serve_http(http_addr).await?;

    tokio::signal::ctrl_c().await?;
    // Shutdown all tasks
    if let Some(task) = stun_task {
        task.abort();
    }
    http_task.abort();
    derp_server.shutdown().await;

    Ok(())
}

const NO_CONTENT_CHALLENGE_HEADER: &str = "X-Tailscale-Challenge";
const NO_CONTENT_RESPONSE_HEADER: &str = "X-Tailscale-Response";

const NOTFOUND: &[u8] = b"Not Found";
const DERP_DISABLED: &[u8] = b"derp server disabled";
const ROBOTS_TXT: &[u8] = b"User-agent: *\nDisallow: /\n";
const INDEX: &[u8] = br#"<html><body>
<h1>DERP</h1>
<p>
  This is an
  <a href="https://iroh.computer/">Iroh</a> DERP
  server.
</p>
"#;

const TLS_HEADERS: [(&str, &str); 2] = [
    ("Strict-Transport-Security", "max-age=63072000; includeSubDomains"),
    ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'self'; block-all-mixed-content; plugin-types 'none'")
];

async fn serve_http(addr: SocketAddr) -> Result<tokio::task::JoinHandle<()>> {
    let http_listener = TcpListener::bind(&addr)
        .await
        .context("failed to bind http")?;
    let http_addr = http_listener.local_addr()?;
    info!("[HTTP]: serving on {}", http_addr);

    let task = tokio::spawn(async move {
        loop {
            match http_listener.accept().await {
                Ok((stream, peer_addr)) => {
                    debug!("[HTTP] Connection opened from {}", peer_addr);
                    let handler = HttpService;

                    tokio::task::spawn(async move {
                        if let Err(err) = Http::new()
                            .serve_connection(derp::MaybeTlsStreamServer::Plain(stream), handler)
                            .with_upgrades()
                            .await
                        {
                            error!("[HTTP] Failed to serve connection: {:?}", err);
                        }
                    });
                }
                Err(err) => {
                    error!("[HTTP] failed to accept connection: {:#?}", err);
                }
            }
        }
    });
    Ok(task)
}

#[derive(Clone)]
struct HttpService;

impl hyper::service::Service<Request<Body>> for HttpService {
    type Response = Response<Body>;
    type Error = HyperError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        match (req.method(), req.uri().path()) {
            // Captive Portal checker
            (&Method::GET, "/generate_204") => {
                Box::pin(serve_no_content_handler(req, Response::builder()))
            }
            _ => {
                // Return 404 not found response.
                let r = Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(NOTFOUND.into())
                    .unwrap();
                Box::pin(async move { Ok(r) })
            }
        }
    }
}

fn derp_disabled_handler(response: ResponseBuilder) -> HyperResult<Response<Body>> {
    Ok(response
        .status(StatusCode::NOT_FOUND)
        .body(DERP_DISABLED.into())
        .unwrap())
}

fn root_handler(response: ResponseBuilder) -> HyperResult<Response<Body>> {
    let response = response
        .status(StatusCode::OK)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(INDEX.into())
        .unwrap();

    Ok(response)
}

/// HTTP latency queries
fn probe_handler(response: ResponseBuilder) -> HyperResult<Response<Body>> {
    let response = response
        .status(StatusCode::OK)
        .header("Access-Control-Allow-Origin", "*")
        .body(Body::empty())
        .unwrap();

    Ok(response)
}

fn robots_handler(response: ResponseBuilder) -> HyperResult<Response<Body>> {
    Ok(response
        .status(StatusCode::OK)
        .body(ROBOTS_TXT.into())
        .unwrap())
}

/// For captive portal detection.
async fn serve_no_content_handler(
    r: Request<Body>,
    mut response: ResponseBuilder,
) -> HyperResult<Response<Body>> {
    if let Some(challenge) = r.headers().get(NO_CONTENT_CHALLENGE_HEADER) {
        if !challenge.is_empty()
            && challenge.len() < 64
            && challenge
                .as_bytes()
                .iter()
                .all(|c| is_challenge_char(*c as char))
        {
            response = response.header(
                NO_CONTENT_RESPONSE_HEADER,
                format!("response {}", challenge.to_str()?),
            );
        }
    }

    Ok(response
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .unwrap())
}

fn is_challenge_char(c: char) -> bool {
    // Semi-randomly chosen as a limited set of valid characters
    c.is_ascii_lowercase()
        || c.is_ascii_uppercase()
        || c.is_ascii_digit()
        || c == '.'
        || c == '-'
        || c == '_'
}

async fn serve_stun(host: IpAddr, port: u16) {
    match UdpSocket::bind((host, port)).await {
        Ok(sock) => {
            let addr = sock.local_addr().expect("socket just bound");
            info!(%addr, "running STUN server");
            server_stun_listener(sock)
                .instrument(debug_span!("stun_server", %addr))
                .await;
        }
        Err(err) => {
            error!("failed to open STUN listener: {:#?}", err);
        }
    }
}

async fn server_stun_listener(sock: UdpSocket) {
    let sock = Arc::new(sock);
    let mut buffer = vec![0u8; 64 << 10];
    loop {
        match sock.recv_from(&mut buffer).await {
            Ok((n, src_addr)) => {
                let pkt = buffer[..n].to_vec();
                let sock = sock.clone();
                tokio::task::spawn(async move {
                    if !stun::is(&pkt) {
                        debug!(%src_addr, "STUN: ignoring non stun packet");
                        return;
                    }
                    match tokio::task::spawn_blocking(move || stun::parse_binding_request(&pkt))
                        .await
                        .unwrap()
                    {
                        Ok(txid) => {
                            debug!(%src_addr, %txid, "STUN: received binding request");
                            let res =
                                tokio::task::spawn_blocking(move || stun::response(txid, src_addr))
                                    .await
                                    .unwrap();
                            match sock.send_to(&res, src_addr).await {
                                Ok(len) => {
                                    if len != res.len() {
                                        warn!(%src_addr, %txid, "STUN: failed to write response sent: {}, but exepcted {}", len, res.len());
                                    }
                                    trace!(%src_addr, %txid, "STUN: sent {} bytes", len);
                                }
                                Err(err) => {
                                    warn!(%src_addr, %txid, "STUN: failed to write response: {:?}", err);
                                }
                            }
                        }
                        Err(err) => {
                            warn!(%src_addr, "STUN: invalid binding request: {:?}", err);
                        }
                    }
                });
            }
            Err(err) => {
                warn!("STUN: failed to recv: {:?}", err);
            }
        }
    }
}

// var validProdHostname = regexp.MustCompile(`^derp([^.]*)\.tailscale\.com\.?$`)

// func prodAutocertHostPolicy(_ context.Context, host string) error {
// 	if validProdHostname.MatchString(host) {
// 		return nil
// 	}
// 	return errors.New("invalid hostname")
// }

// func defaultMeshPSKFile() string {
// 	try := []string{
// 		"/home/derp/keys/derp-mesh.key",
// 		filepath.Join(os.Getenv("HOME"), "keys", "derp-mesh.key"),
// 	}
// 	for _, p := range try {
// 		if _, err := os.Stat(p); err == nil {
// 			return p
// 		}
// 	}
// 	return ""
// }

// func rateLimitedListenAndServeTLS(srv *http.Server) error {
// 	addr := srv.Addr
// 	if addr == "" {
// 		addr = ":https"
// 	}
// 	ln, err := net.Listen("tcp", addr)
// 	if err != nil {
// 		return err
// 	}
// 	rln := newRateLimitedListener(ln, rate.Limit(*acceptConnLimit), *acceptConnBurst)
// 	expvar.Publish("tls_listener", rln.ExpVar())
// 	defer rln.Close()
// 	return srv.ServeTLS(rln, "", "")
// }

// type rateLimitedListener struct {
// 	// These are at the start of the struct to ensure 64-bit alignment
// 	// on 32-bit architecture regardless of what other fields may exist
// 	// in this package.
// 	numAccepts expvar.Int // does not include number of rejects
// 	numRejects expvar.Int

// 	net.Listener

// 	lim *rate.Limiter
// }

// func newRateLimitedListener(ln net.Listener, limit rate.Limit, burst int) *rateLimitedListener {
// 	return &rateLimitedListener{Listener: ln, lim: rate.NewLimiter(limit, burst)}
// }

// func (l *rateLimitedListener) ExpVar() expvar.Var {
// 	m := new(metrics.Set)
// 	m.Set("counter_accepted_connections", &l.numAccepts)
// 	m.Set("counter_rejected_connections", &l.numRejects)
// 	return m
// }

// var errLimitedConn = errors.New("cannot accept connection; rate limited")

// func (l *rateLimitedListener) Accept() (net.Conn, error) {
// 	// Even under a rate limited situation, we accept the connection immediately
// 	// and close it, rather than being slow at accepting new connections.
// 	// This provides two benefits: 1) it signals to the client that something
// 	// is going on on the server, and 2) it prevents new connections from
// 	// piling up and occupying resources in the OS kernel.
// 	// The client will retry as needing (with backoffs in place).
// 	cn, err := l.Listener.Accept()
// 	if err != nil {
// 		return nil, err
// 	}
// 	if !l.lim.Allow() {
// 		l.numRejects.Add(1)
// 		cn.Close()
// 		return nil, errLimitedConn
// 	}
// 	l.numAccepts.Add(1)
// 	return cn, nil
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_serve_no_content_handler() {
        let challenge = "123az__.";
        let req = Request::builder()
            .header(NO_CONTENT_CHALLENGE_HEADER, challenge)
            .body(Body::empty())
            .unwrap();

        let res = serve_no_content_handler(req, Response::builder())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        let header = res
            .headers()
            .get(NO_CONTENT_RESPONSE_HEADER)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(header, format!("response {challenge}"));
        assert!(hyper::body::to_bytes(res.into_body())
            .await
            .unwrap()
            .is_empty());
    }

    #[test]
    fn test_escape_hostname() {
        assert_eq!(
            escape_hostname("hello.host.name_foo-bar%baz"),
            "hello.host.namefoo-barbaz"
        );
    }
}
