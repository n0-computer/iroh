//! Relay-transport throughput benchmark using a real `transfer` process.
//!
//! Builds a patchbay network (linux, rootless user namespaces) with one relay
//! and two peers behind symmetric NATs, then runs the release-built `transfer`
//! example as a real OS process inside each peer's namespace via
//! [`Device::spawn_command`]. This measures the relay transport end to end
//! without the in-process test harness as a variable, and lets a driver script
//! sweep framings, conditions, and durations by passing args straight through.
//!
//! Patchbay-specific args come first; everything after `--` is passed through to
//! both the `provide` and `fetch` `transfer` invocations (e.g.
//! `-- --relay-transport wt-uni`). The parent environment (RUST_LOG, etc.) is
//! inherited by the transfer processes, so trace logging propagates.
//!
//! Not linux: the example is a no-op stub (patchbay is linux-only).
//!
//! Example:
//!   cargo build --release -p iroh --features test-utils --example transfer
//!   cargo run --release -p iroh --features test-utils --example relay_bench -- \
//!     --transfer-bin target/release/examples/transfer \
//!     --degradation wifi --duration 10 -- --relay-transport wt-uni

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("relay_bench requires linux (patchbay uses user namespaces)");
}

#[cfg(target_os = "linux")]
fn main() -> n0_error::Result<()> {
    // Log the in-process relay server to stderr under RUST_LOG (quiet when
    // unset), so `--log-dir` captures the server side of a run alongside the
    // per-role transfer logs.
    use tracing_subscriber::{EnvFilter, fmt};
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    // Must init user namespaces before any threads are spawned (unshare of the
    // user namespace fails on a multithreaded process), so do it before building
    // the tokio runtime.
    patchbay::init_userns().map_err(|e| n0_error::anyerr!("init user namespaces: {e}"))?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| n0_error::anyerr!("build runtime: {e}"))?;
    rt.block_on(imp::run())
}

#[cfg(target_os = "linux")]
mod imp {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        path::PathBuf,
        process::Stdio,
        sync::Mutex,
        time::Duration,
    };

    use clap::{Parser, ValueEnum};
    use n0_error::{Result, StdResultExt, anyerr, bail_any};
    use patchbay::{
        IfaceConfig, IpSupport, Lab, LinkCondition, LinkDirection, LinkLimits, Nat, OutDir,
    };
    use tokio::{
        io::{AsyncBufReadExt, BufReader},
        process::Command,
        sync::oneshot,
        time::timeout,
    };

    /// Link condition applied to both peers' access links, both directions.
    #[derive(Debug, Clone, Copy, ValueEnum)]
    enum Degradation {
        /// No impairment.
        Lan,
        /// Good 5 GHz WiFi.
        Wifi,
        /// 4G/LTE, good signal.
        #[value(name = "4g")]
        Mobile4g,
        /// 3G or degraded 4G (2 Mbit cap, 2% loss).
        #[value(name = "3g")]
        Mobile3g,
    }

    /// How a `Degradation` is turned into concrete link limits.
    ///
    /// The presets model last-mile loss as independent per-packet netem loss on
    /// an otherwise uncapped link. That is convenient but makes run-to-run
    /// variance high (the congestion window settles against random loss
    /// differently each run) and lets a loss-based controller collapse far below
    /// what a real, bandwidth-limited link would allow. The `capped` and
    /// `congestion` models trade some of that away for realism and repeatability.
    #[derive(Debug, Clone, Copy, PartialEq, ValueEnum)]
    enum LinkModel {
        /// The patchbay presets: uncapped (except 3g) with independent per-packet
        /// (Bernoulli) loss. Highest variance; kept as the historical baseline.
        Preset,
        /// Preset latency/jitter/loss plus a realistic bandwidth cap. Bounds the
        /// high end without changing the loss process, so a loss-based controller
        /// still collapses -- but against a fixed ceiling.
        Capped,
        /// Bandwidth cap plus a buffer sized near the path RTT and no independent
        /// radio loss: packet loss emerges from buffer overflow (congestion), as
        /// on a real bottleneck. Most repeatable; isolates bufferbloat behaviour.
        Congestion,
        /// The most faithful model, and the default: a bandwidth cap, an RTT-sized
        /// buffer (so loss also emerges from congestion instead of only bufferbloat
        /// at a fixed 400 ms), and bursty Gilbert-Elliott radio loss (real links
        /// fade and hand over in bursts). Combines the realism of `congestion`
        /// with the radio loss that a real last-mile link actually has.
        Realistic,
    }

    impl Degradation {
        /// (latency_ms, jitter_ms, rate_kbit cap, preset loss %, congestion buffer_ms).
        ///
        /// The cap and buffer are only used by the `capped`/`congestion` models.
        /// Buffers are ~1.5x the bandwidth-delay product (path RTT ~= 4x one-way
        /// latency over the two access links), so a loss-based controller
        /// bufferbloats to ~1.5 BDP before the queue drops.
        fn params(self) -> (u32, u32, u32, f32, u32) {
            match self {
                Degradation::Lan => (0, 0, 0, 0.0, 0),
                Degradation::Wifi => (5, 2, 150_000, 0.1, 30),
                Degradation::Mobile4g => (25, 8, 35_000, 0.5, 150),
                Degradation::Mobile3g => (100, 30, 2_000, 2.0, 600),
            }
        }

        /// `loss_burst` (mean burst length in packets, 0/1 = Bernoulli) makes the
        /// `capped` and `realistic` models' radio loss bursty (Gilbert-Elliott),
        /// as on a real fading link. For `realistic` a `0` means "use the model's
        /// default burst"; for `capped` a `0` means Bernoulli. It has no effect on
        /// `preset` (fixed presets) or `congestion` (no radio loss).
        fn condition(self, model: LinkModel, loss_burst: u32) -> LinkCondition {
            if model == LinkModel::Preset {
                return match self {
                    Degradation::Lan => LinkCondition::Lan,
                    Degradation::Wifi => LinkCondition::Wifi,
                    Degradation::Mobile4g => LinkCondition::Mobile4G,
                    Degradation::Mobile3g => LinkCondition::Mobile3G,
                };
            }
            let (latency_ms, jitter_ms, rate_kbit, loss_pct, buffer_ms) = self.params();
            let mut limits = LinkLimits {
                latency_ms,
                jitter_ms,
                rate_kbit,
                ..Default::default()
            };
            match model {
                // Keep the preset's random loss and the default (400ms) tbf buffer.
                LinkModel::Capped => {
                    limits.loss_pct = loss_pct;
                    limits.loss_burst_pkts = loss_burst;
                }
                // No radio loss; loss comes from the RTT-sized buffer overflowing.
                LinkModel::Congestion => limits.buffer_ms = buffer_ms,
                // RTT-sized buffer (congestion loss) plus bursty radio loss.
                LinkModel::Realistic => {
                    limits.buffer_ms = buffer_ms;
                    limits.loss_pct = loss_pct;
                    limits.loss_burst_pkts = if loss_burst > 0 { loss_burst } else { 8 };
                }
                LinkModel::Preset => unreachable!(),
            }
            LinkCondition::Manual(limits)
        }
    }

    #[derive(Parser, Debug, Clone)]
    #[command(name = "relay_bench")]
    struct Args {
        /// Path to the release-built `transfer` example binary.
        #[clap(long)]
        transfer_bin: PathBuf,
        /// Directory for per-role trace logs. When set, the provider's and
        /// fetcher's stderr go to `<dir>/provider.log` and `<dir>/fetcher.log`
        /// (RUST_LOG is inherited by both). When unset, both inherit our stderr.
        #[clap(long)]
        log_dir: Option<PathBuf>,
        /// Link condition applied to both peers.
        #[clap(long, value_enum, default_value = "wifi")]
        degradation: Degradation,
        /// How the `--degradation` is realized: `realistic` (default; cap +
        /// RTT-sized buffer + bursty radio loss), `preset` (uncapped, per-packet
        /// loss), `capped` (preset + bandwidth cap), or `congestion` (cap +
        /// RTT-sized buffer, loss from overflow only). See `LinkModel`.
        #[clap(long, value_enum, default_value = "realistic")]
        link_model: LinkModel,
        /// Mean loss-burst length in packets for the `capped`/`realistic` models'
        /// radio loss. `0`/`1` = independent per-packet (Bernoulli) loss; `>= 2`
        /// switches to bursty Gilbert-Elliott loss at the same long-run rate. For
        /// `realistic`, `0` uses the model's default burst length.
        #[clap(long, default_value_t = 0)]
        loss_burst: u32,
        /// Link MTU for every link.
        #[clap(long, default_value_t = 1400)]
        mtu: u32,
        /// Transfer mode for the fetcher (download|upload|bidi).
        #[clap(long, default_value = "download")]
        mode: String,
        /// Limit the transfer duration, in seconds (mutually exclusive with --size).
        #[clap(long, conflicts_with = "size")]
        duration: Option<u64>,
        /// Limit the transferred size, in bytes.
        #[clap(long)]
        size: Option<u64>,
        /// Overall timeout for the whole run, in seconds.
        #[clap(long, default_value_t = 180)]
        timeout: u64,
        /// Run relay + provider + fetcher as plain loopback processes on
        /// 127.0.0.1 with no patchbay namespaces, NAT, or netem -- a
        /// no-namespacing baseline. `--degradation` is ignored in this mode; the
        /// peers are forced onto the relay path with `--relay-only`.
        #[clap(long)]
        localhost: bool,
        /// Args passed through to both `transfer` invocations (after `--`).
        #[clap(last = true)]
        passthrough: Vec<String>,
    }

    /// Which transfer process is being spawned.
    #[derive(Debug, Clone, Copy)]
    enum Role {
        Provider,
        Fetcher,
    }

    /// Process-global list of spawned child PIDs (provider, fetcher) so they can
    /// be SIGKILLed from any exit path, including the overall-timeout path in
    /// [`run`], which cannot rely on `Drop`: on a hung transfer, dropping the
    /// `Lab` blocks joining a namespace worker thread stuck on the hung child.
    ///
    /// `spawn_command` registers each child with a per-namespace tokio runtime,
    /// so killing/reaping through the `tokio::process::Child` handle from the
    /// main runtime is unreliable -- `start_kill`/`wait` report success while
    /// the OS process keeps running, leaking a `transfer` server that then skews
    /// later runs. Killing by raw PID with `libc::kill` is runtime-independent;
    /// PIDs are global because patchbay isolates the network namespace, not the
    /// PID namespace, so the signal reaches the child from our namespace.
    static CHILD_PIDS: Mutex<Vec<u32>> = Mutex::new(Vec::new());

    fn register_child(child: &tokio::process::Child) {
        if let Some(pid) = child.id() {
            CHILD_PIDS.lock().expect("child pid lock").push(pid);
        }
    }

    fn kill_children() {
        for pid in CHILD_PIDS.lock().expect("child pid lock").drain(..) {
            // SAFETY: `kill` is always safe to call; an invalid or already-exited
            // PID just yields ESRCH, which we ignore.
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGKILL);
            }
        }
    }

    /// Per-run measurement parsed from the fetcher's JSON output: the goodput
    /// plus the tunneled p2p connection's packet/loss/batching counters.
    #[derive(Default, Debug)]
    struct RunStats {
        bytes: u64,
        secs: f64,
        udp_tx_datagrams: u64,
        udp_tx_ios: u64,
        udp_rx_datagrams: u64,
        udp_rx_ios: u64,
        lost_packets: u64,
        lost_bytes: u64,
        cwnd: u64,
        rtt_us: u64,
    }

    /// The stderr sink for a `transfer` child: a per-role log file under
    /// `--log-dir` if set, else our inherited stderr.
    fn role_stderr(args: &Args, role: &str) -> Result<Stdio> {
        match &args.log_dir {
            Some(dir) => {
                std::fs::create_dir_all(dir).std_context("create log dir")?;
                let file = std::fs::File::create(dir.join(format!("{role}.log")))
                    .std_context("create role log")?;
                Ok(Stdio::from(file))
            }
            None => Ok(Stdio::inherit()),
        }
    }

    pub(super) async fn run() -> Result<()> {
        let args = Args::parse();
        let timeout_secs = args.timeout;
        // Run the benchmark on a spawned task so the overall timeout can fire
        // without dropping (and thus tearing down) the `Lab` inline: on a hung
        // transfer, dropping the `Lab` blocks joining a stuck namespace worker
        // thread. On timeout we SIGKILL the children and exit the process hard,
        // letting the kernel reclaim the rootless namespaces.
        let handle = if args.localhost {
            tokio::spawn(run_localhost(args))
        } else {
            tokio::spawn(run_inner(args))
        };
        match timeout(Duration::from_secs(timeout_secs), handle).await {
            Ok(Ok(res)) => {
                kill_children();
                res
            }
            Ok(Err(join_err)) => {
                kill_children();
                bail_any!("benchmark task panicked: {join_err}")
            }
            Err(_elapsed) => {
                kill_children();
                eprintln!("RELAYBENCH TIMEOUT after {timeout_secs}s");
                std::process::exit(2);
            }
        }
    }

    async fn run_inner(args: Args) -> Result<()> {
        let lab = Lab::builder()
            .outdir(OutDir::Nested(std::env::temp_dir().join("relay-bench")))
            .build()
            .await?;

        // Public backbone + relay device.
        let net = lab
            .add_router("net")
            .ip_support(IpSupport::DualStack)
            .mtu(args.mtu)
            .build()
            .await?;
        let relay_dev = lab
            .add_device("relay")
            .uplink(net.id())
            .mtu(args.mtu)
            .build()
            .await?;
        let relay_ip: IpAddr = relay_dev.ip().std_context("relay has no v4")?.into();

        // Spawn the relay server in-process inside the relay device's namespace.
        let (ready_tx, ready_rx) = oneshot::channel();
        let _relay_task = relay_dev.spawn(async move |_ctx| {
            let server = relay::spawn_relay(Ipv6Addr::UNSPECIFIED.into(), 80, 443, 7842)
                .await
                .expect("spawn relay");
            ready_tx.send(()).ok();
            std::future::pending::<()>().await;
            drop(server);
        })?;
        ready_rx.await.std_context("relay startup")?;
        let relay_url = format!("https://{relay_ip}");

        // Two peers behind their own symmetric NAT (relay stays the only path,
        // IP transports and GSO remain enabled).
        let condition = args.degradation.condition(args.link_model, args.loss_burst);
        let nat_provider = lab
            .add_router("nat-provider")
            .nat(Nat::Corporate)
            .mtu(args.mtu)
            .build()
            .await?;
        let nat_fetcher = lab
            .add_router("nat-fetcher")
            .nat(Nat::Corporate)
            .mtu(args.mtu)
            .build()
            .await?;
        let provider_dev = lab
            .add_device("provider")
            .iface(
                "eth0",
                IfaceConfig::routed(nat_provider.id()).condition(condition, LinkDirection::Both),
            )
            .mtu(args.mtu)
            .build()
            .await?;
        let fetcher_dev = lab
            .add_device("fetcher")
            .iface(
                "eth0",
                IfaceConfig::routed(nat_fetcher.id()).condition(condition, LinkDirection::Both),
            )
            .mtu(args.mtu)
            .build()
            .await?;

        // Provider and fetcher run as real processes in their peer namespaces
        // via `spawn_command`. The Corporate NATs already force the relay path,
        // so `--relay-only` is not needed here.
        let deg_label = format!("{:?}", args.degradation);
        run_transfers(&args, &relay_url, &deg_label, false, |role, cmd| {
            let dev = match role {
                Role::Provider => &provider_dev,
                Role::Fetcher => &fetcher_dev,
            };
            dev.spawn_command(cmd)
                .map_err(|e| anyerr!("spawn {role:?}: {e}"))
        })
        .await
    }

    /// No-namespacing baseline: relay + provider + fetcher as plain loopback
    /// processes on 127.0.0.1, with `--relay-only` so the peers use the relay
    /// path rather than discovering a direct loopback connection.
    async fn run_localhost(args: Args) -> Result<()> {
        // Fixed high ports (no root for :443 in the host namespace). H3/WT is
        // served on the TLS port over UDP; the QAD QUIC endpoint is separate.
        const HTTPS_PORT: u16 = 38443;
        let bind_ip: IpAddr = Ipv4Addr::LOCALHOST.into();
        let (ready_tx, ready_rx) = oneshot::channel();
        let _relay_task = tokio::spawn(async move {
            let server = relay::spawn_relay(bind_ip, 38080, HTTPS_PORT, 37842)
                .await
                .expect("spawn relay");
            ready_tx.send(()).ok();
            std::future::pending::<()>().await;
            drop(server);
        });
        ready_rx.await.std_context("relay startup")?;
        let relay_url = format!("https://127.0.0.1:{HTTPS_PORT}");
        run_transfers(&args, &relay_url, "Localhost", true, |_role, mut cmd| {
            cmd.spawn().map_err(|e| anyerr!("spawn transfer: {e}"))
        })
        .await
    }

    /// Spawn the provider and fetcher `transfer` processes against `relay_url`,
    /// read the fetcher's stats, and print the `RELAYBENCH` line. `spawn` places
    /// each child in the right place (a peer namespace, or plain loopback).
    async fn run_transfers<F>(
        args: &Args,
        relay_url: &str,
        deg_label: &str,
        relay_only: bool,
        spawn: F,
    ) -> Result<()>
    where
        F: Fn(Role, Command) -> Result<tokio::process::Child>,
    {
        // --- Provider ---
        // No IROH_SECRET: each run gets a fresh random endpoint id, which the
        // benchmark reads from stdout anyway. Fixed ids risked a stray leaked
        // provider from a prior run colliding on the relay.
        let mut provide_cmd = Command::new(&args.transfer_bin);
        provide_cmd
            .arg("--output")
            .arg("json")
            .arg("provide")
            .arg("--relay-url")
            .arg(relay_url)
            .arg("--insecure")
            .arg("--no-pkarr-publish")
            .arg("--no-dns-resolve");
        if relay_only {
            provide_cmd.arg("--relay-only");
        }
        provide_cmd
            .args(&args.passthrough)
            .stdout(Stdio::piped())
            .stderr(role_stderr(args, "provider")?);
        let mut provider = spawn(Role::Provider, provide_cmd)?;
        register_child(&provider);
        let provider_out = provider.stdout.take().std_context("provider stdout")?;

        // Read provider stdout until it announces its endpoint id, then keep
        // draining the rest in the background. The provider runs with
        // `--output json` and writes a JSON line per event for the whole run;
        // if we stop reading, its stdout pipe fills, its next `println!` hits a
        // broken pipe and panics, tearing down the connection before the
        // transfer completes. Draining to EOF keeps the read end open.
        let mut provider_lines = BufReader::new(provider_out).lines();
        let provider_id = read_endpoint_id(&mut provider_lines)
            .await
            .std_context("read provider endpoint id")?;
        eprintln!("provider endpoint id: {provider_id}");
        let _drain = tokio::spawn(async move {
            while let Ok(Some(_line)) = provider_lines.next_line().await {}
        });

        // --- Fetcher ---
        let mut fetch_cmd = Command::new(&args.transfer_bin);
        fetch_cmd
            .arg("--output")
            .arg("json")
            .arg("fetch")
            .arg(&provider_id)
            .arg("--mode")
            .arg(&args.mode);
        if let Some(d) = args.duration {
            fetch_cmd.arg("--duration").arg(d.to_string());
        }
        if let Some(s) = args.size {
            fetch_cmd.arg("--size").arg(s.to_string());
        }
        fetch_cmd
            .arg("--relay-url")
            .arg(relay_url)
            .arg("--remote-relay-url")
            .arg(relay_url)
            .arg("--insecure")
            .arg("--no-pkarr-publish")
            .arg("--no-dns-resolve");
        if relay_only {
            fetch_cmd.arg("--relay-only");
        }
        fetch_cmd
            .args(&args.passthrough)
            .stdout(Stdio::piped())
            .stderr(role_stderr(args, "fetcher")?);
        let mut fetcher = spawn(Role::Fetcher, fetch_cmd)?;
        register_child(&fetcher);
        let fetcher_out = fetcher.stdout.take().std_context("fetcher stdout")?;

        // Read fetcher stdout, echoing JSON lines and capturing the transfer
        // stats. This drains to EOF, which happens when the fetcher exits (its
        // transfer is size- or duration-bounded). `run` then SIGKILLs both
        // children.
        let result = read_transfer_result(fetcher_out).await;

        match result {
            Some(s) => {
                let mbps = (s.bytes as f64 * 8.0 / 1_000_000.0) / s.secs;
                println!(
                    "RELAYBENCH bytes={} secs={:.3} mbps={mbps:.2} mode={} degradation={deg_label} \
                     udp_tx_datagrams={} udp_tx_ios={} udp_rx_datagrams={} udp_rx_ios={} \
                     lost_packets={} lost_bytes={} cwnd={} rtt_us={}",
                    s.bytes,
                    s.secs,
                    args.mode,
                    s.udp_tx_datagrams,
                    s.udp_tx_ios,
                    s.udp_rx_datagrams,
                    s.udp_rx_ios,
                    s.lost_packets,
                    s.lost_bytes,
                    s.cwnd,
                    s.rtt_us,
                );
            }
            None => bail_any!("fetcher produced no transfer stats"),
        }
        Ok(())
    }

    /// Read newline-delimited JSON from the provider until an `endpoint_id`
    /// field appears, returning it. Leaves the reader positioned after that
    /// line so the caller can keep draining the rest.
    async fn read_endpoint_id<R: tokio::io::AsyncRead + Unpin>(
        lines: &mut tokio::io::Lines<BufReader<R>>,
    ) -> Result<String> {
        while let Some(line) = lines.next_line().await.std_context("read line")? {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                if let Some(id) = v.get("endpoint_id").and_then(|v| v.as_str()) {
                    return Ok(id.to_string());
                }
            }
        }
        bail_any!("provider stdout ended before announcing endpoint id")
    }

    /// Read newline-delimited JSON from the fetcher, echoing each line, and
    /// collect a [`RunStats`]: goodput from the first transfer-stats line (both
    /// `size` and `duration` present, duration in microseconds), plus the
    /// tunneled connection counters from the `ConnStats` and `PathStats` events.
    /// Returns `None` if no transfer-stats line ever arrives.
    async fn read_transfer_result<R: tokio::io::AsyncRead + Unpin>(reader: R) -> Option<RunStats> {
        let mut lines = BufReader::new(reader).lines();
        let mut stats = RunStats::default();
        let mut got_transfer = false;
        while let Ok(Some(line)) = lines.next_line().await {
            eprintln!("fetch: {line}");
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };
            let kind = v.get("kind").and_then(|k| k.as_str());
            // The transfer-stats line (DownloadComplete/UploadComplete) carries
            // both size and duration at the top level.
            if !got_transfer
                && let (Some(size), Some(dur_us)) = (
                    v.get("size").and_then(|v| v.as_u64()),
                    v.get("duration").and_then(|v| v.as_u64()),
                )
            {
                stats.bytes = size;
                stats.secs = dur_us as f64 / 1_000_000.0;
                got_transfer = true;
            }
            match kind {
                Some("ConnStats") => {
                    stats.udp_tx_datagrams = json_u64(&v, "udp_tx_datagrams");
                    stats.udp_tx_ios = json_u64(&v, "udp_tx_ios");
                    stats.udp_rx_datagrams = json_u64(&v, "udp_rx_datagrams");
                    stats.udp_rx_ios = json_u64(&v, "udp_rx_ios");
                    stats.lost_packets = json_u64(&v, "lost_packets");
                    stats.lost_bytes = json_u64(&v, "lost_bytes");
                }
                Some("PathStats") => {
                    if let Some(p) = v
                        .get("paths")
                        .and_then(|p| p.as_array())
                        .and_then(|a| a.first())
                    {
                        stats.cwnd = json_u64(p, "cwnd");
                        stats.rtt_us = json_u64(p, "rtt");
                    }
                }
                _ => {}
            }
        }
        got_transfer.then_some(stats)
    }

    /// Read a `u64` field from a JSON object, defaulting to 0 when absent.
    fn json_u64(v: &serde_json::Value, key: &str) -> u64 {
        v.get(key).and_then(|x| x.as_u64()).unwrap_or(0)
    }

    mod relay {
        use std::net::IpAddr;

        use iroh_relay::server::{
            AllowAll, CertConfig, QuicConfig, RelayConfig as RelayServerConfig, Server,
            ServerConfig, SpawnError, TlsConfig, testing::self_signed_tls_certs_and_config,
        };

        /// Spawn a relay server with a self-signed cert and H3/WebTransport
        /// enabled, bound to `bind_ip` on the given ports (HTTP, HTTPS+H3, QUIC).
        /// H3/WT is served on the HTTPS port over UDP. Clients connect with
        /// `--insecure`.
        pub(super) async fn spawn_relay(
            bind_ip: IpAddr,
            http_port: u16,
            https_port: u16,
            quic_port: u16,
        ) -> Result<Server, SpawnError> {
            let (_certs, server_config) = self_signed_tls_certs_and_config();
            let tls = TlsConfig::new((bind_ip, https_port), CertConfig::Manual { server_config });
            let mut relay = RelayServerConfig::new((bind_ip, http_port));
            relay.tls = Some(tls);
            relay.key_cache_capacity = Some(1024);
            relay.access = std::sync::Arc::new(AllowAll);
            let mut config = ServerConfig::default();
            config.relay = Some(relay);
            config.quic = Some(QuicConfig::new((bind_ip, quic_port)));
            Server::spawn(config).await
        }
    }
}
