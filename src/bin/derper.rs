//! A simple DERP server.
//!
//! Based on /tailscale/cmd/derper

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use hyper::{
    service::{make_service_fn, service_fn},
    Body, Method, Request, Response, StatusCode,
};
use iroh::hp::{key, stun};
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;
use tracing::{error, info, warn};
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
    #[clap(long, short, default_value = "0.0.0.0:443")]
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
    #[clap(long, value_enum, default_value_t = CertMode::LetsEncrypt)]
    cert_mode: CertMode,
    /// Directory to store LetsEncrypt certs, if addr's port is :443
    #[clap(long)]
    // Default: tsweb.DefaultCertDir("derper-certs"), "")
    cert_dir: Option<PathBuf>,
    /// LetsEncrypt host name, if addr's port is :443.
    #[clap(long, default_value = "derp.iroh.computer")]
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

// stunReadError  = stunDisposition.Get("read_error")
// stunNotSTUN    = stunDisposition.Get("not_stun")
// stunWriteError = stunDisposition.Get("write_error")
// stunSuccess    = stunDisposition.Get("success")

// stunIPv4 = stunAddrFamily.Get("ipv4")
// stunIPv6 = stunAddrFamily.Get("ipv6")

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

    let mut tasks = JoinSet::new();

    if cli.dev {
        cli.addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), DEV_PORT);
        info!("Running in dev mode.");
    }

    let listen_host = cli.addr.ip();
    let serve_tls = cli.addr.port() == 443 || CertMode::Manual == cli.cert_mode;

    let derper_service = make_service_fn(move |_| async {
        Ok::<_, HyperError>(service_fn(move |req| response_handler(req)))
    });

    let derp_handler = if cli.run_derp {
        let cfg = Config::load(&cli).await?;
        // 	s := derp.NewServer(cfg.PrivateKey, log.Printf)
        // 	s.SetVerifyClient(*verifyClients)

        if let Some(file) = cli.mesh_psk_file {
            let raw = tokio::fs::read_to_string(file)
                .await
                .context("reading mesh-pks file")?;
            let mut mesh_key = [0u8; 32];
            hex::decode_to_slice(raw.trim(), &mut mesh_key).context("invalid mesh-pks content")?;
            info!("DERP mesh key configured");
            // 	if err := startMesh(s); err != nil {
            // 		log.Fatalf("startMesh: %v", err)
            // 	}
        }

        // 		derpHandler := derphttp.Handler(s)
        // 		derpHandler = addWebSocketSupport(s, derpHandler)
        // 		mux.Handle("/derp", derpHandler)
        todo!()
    } else {
        derp_disabled_handler
    };

    if cli.run_stun {
        tasks.spawn(async move { serve_stun(listen_host, cli.stun_port).await });
    }

    if serve_tls {
        info!("derper: serving on {} with TLS", cli.addr);
        // 		var certManager certProvider
        // 		certManager, err = certProviderByCertMode(*certMode, *certDir, *hostname)
        // 		if err != nil {
        // 			log.Fatalf("derper: can not start cert provider: %v", err)
        // 		}
        // 		httpsrv.TLSConfig = certManager.TLSConfig()
        // 		getCert := httpsrv.TLSConfig.GetCertificate
        // 		httpsrv.TLSConfig.GetCertificate = func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
        // 			cert, err := getCert(hi)
        // 			if err != nil {
        // 				return nil, err
        // 			}
        // 			cert.Certificate = append(cert.Certificate, s.MetaCert())
        // 			return cert, nil
        // 		}
        // 		// Disable TLS 1.0 and 1.1, which are obsolete and have security issues.
        // 		httpsrv.TLSConfig.MinVersion = tls.VersionTLS12
        // 		httpsrv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // 			if r.TLS != nil {
        // 				label := "unknown"
        // 				switch r.TLS.Version {
        // 				case tls.VersionTLS10:
        // 					label = "1.0"
        // 				case tls.VersionTLS11:
        // 					label = "1.1"
        // 				case tls.VersionTLS12:
        // 					label = "1.2"
        // 				case tls.VersionTLS13:
        // 					label = "1.3"
        // 				}
        // 				tlsRequestVersion.Add(label, 1)
        // 				tlsActiveVersion.Add(label, 1)
        // 				defer tlsActiveVersion.Add(label, -1)
        // }
        // 			// Set HTTP headers to appease automated security scanners.
        // 			//
        // 			// Security automation gets cranky when HTTPS sites don't
        // 			// set HSTS, and when they don't specify a content
        // 			// security policy for XSS mitigation.
        // 			//
        // 			// DERP's HTTP interface is only ever used for debug
        // 			// access (for which trivial safe policies work just
        // 			// fine), and by DERP clients which don't obey any of
        // 			// these browser-centric headers anyway.
        // 			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
        // 			w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'self'; block-all-mixed-content; plugin-types 'none'")
        // 			mux.ServeHTTP(w, r)
        // 		})

        // 			go func() {
        // 				port80mux := http.NewServeMux()
        // 				port80mux.HandleFunc("/generate_204", serveNoContent)
        // 				port80mux.Handle("/", certManager.HTTPHandler(tsweb.Port80Handler{Main: mux}))
        // 				port80srv := &http.Server{
        // 					Addr:        net.JoinHostPort(listenHost, fmt.Sprintf("%d", *httpPort)),
        // 					Handler:     port80mux,
        // 					ErrorLog:    quietLogger,
        // 					ReadTimeout: 30 * time.Second,
        // 					// Crank up WriteTimeout a bit more than usually
        // 					// necessary just so we can do long CPU profiles
        // 					// and not hit net/http/pprof's "profile
        // 					// duration exceeds server's WriteTimeout".
        // 					WriteTimeout: 5 * time.Minute,
        // 				}
        // 				err := port80srv.ListenAndServe()
        // 				if err != nil {
        // 					if err != http.ErrServerClosed {
        // 						log.Fatal(err)
        // 					}
        // 				}
        // 			}()
        // 		}
        // 		err = rateLimitedListenAndServeTLS(httpsrv)
    } else {
        info!("derper: serving on {}", cli.addr);
        let server = hyper::Server::bind(&cli.addr).serve(derper_service);
        server.await?;
    }

    // Shutdown all tasks
    tasks.abort_all();

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
  This is a
  <a href="https://iroh.computer/">Iroh</a> DERP
  server.
</p>
"#;

async fn response_handler(req: Request<Body>) -> HyperResult<Response<Body>> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") | (&Method::GET, "/index.html") => root_handler().await,
        // Robots
        (&Method::GET, "/robots.txt") => robots_handler().await,
        // Captive Portal checker
        (&Method::GET, "/generate_204") => serve_no_content_handler(req).await,
        _ => {
            // Return 404 not found response.
            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(NOTFOUND.into())
                .unwrap())
        }
    }
}

async fn derp_disabled_handler() -> HyperResult<Response<Body>> {
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(DERP_DISABLED.into())
        .unwrap())
}

async fn root_handler() -> HyperResult<Response<Body>> {
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(INDEX.into())
        .unwrap();

    Ok(response)
}

async fn robots_handler() -> HyperResult<Response<Body>> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(ROBOTS_TXT.into())
        .unwrap())
}

/// For captive portal detection.
async fn serve_no_content_handler(r: Request<Body>) -> HyperResult<Response<Body>> {
    let mut response = Response::builder();
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
    ('a' <= c && c <= 'z')
        || ('A' <= c && c <= 'Z')
        || ('0' <= c && c <= '9')
        || c == '.'
        || c == '-'
        || c == '_'
}

async fn serve_stun(host: IpAddr, port: u16) {
    match tokio::net::UdpSocket::bind((host, port)).await {
        Ok(pc) => {
            info!("running STUN server on {:?}", pc.local_addr());
            server_stun_listener(pc).await;
        }
        Err(err) => {
            error!("failed to open STUN listener: {:#?}", err);
        }
    }
}

async fn server_stun_listener(pc: tokio::net::UdpSocket) {
    let mut buffer = vec![0u8; 64 << 10];
    loop {
        match pc.recv_from(&mut buffer).await {
            Ok((n, ua)) => {
                let pkt = &buffer[..n];
                if !stun::is(pkt) {
                    continue;
                }
                match stun::parse_binding_request(pkt) {
                    Ok(txid) => {
                        let res = stun::response(txid, ua);
                        if let Err(err) = pc.send_to(&res, ua).await {
                            warn!("STUN: failed to write response to {}: {:?}", ua, err);
                        }
                    }
                    Err(err) => {
                        warn!("STUN: invalid binding request from {}: {:?}", ua, err);
                        continue;
                    }
                }
            }
            Err(err) => {
                warn!("STUN recv: {:?}", err);
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
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

        let res = serve_no_content_handler(req).await.unwrap();
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
}
