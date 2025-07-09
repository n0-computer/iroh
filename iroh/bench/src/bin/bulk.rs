use std::collections::BTreeMap;

use clap::Parser;
#[cfg(not(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")))]
use iroh_bench::quinn;
use iroh_bench::{configure_tracing_subscriber, iroh, rt, s2n, Commands, Opt};
use iroh_metrics::{MetricValue, MetricsGroup};
use n0_snafu::Result;

fn main() {
    let cmd = Commands::parse();
    configure_tracing_subscriber();

    match cmd {
        Commands::Iroh(opt) => {
            if let Err(e) = run_iroh(opt) {
                eprintln!("failed: {e:#}");
            }
        }
        #[cfg(not(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")))]
        Commands::Quinn(opt) => {
            if let Err(e) = run_quinn(opt) {
                eprintln!("failed: {e:#}");
            }
        }
        Commands::S2n(opt) => {
            if let Err(e) = run_s2n(opt) {
                eprintln!("failed: {e:#}");
            }
        }
    }
}

pub fn run_iroh(opt: Opt) -> Result<()> {
    let server_span = tracing::error_span!("server");
    let runtime = rt();

    #[cfg(feature = "local-relay")]
    let (relay_url, relay_server) = if opt.only_relay {
        let (_, relay_url, relay_server) =
            runtime.block_on(::iroh::test_utils::run_relay_server())?;

        (Some(relay_url), Some(relay_server))
    } else {
        (None, None)
    };
    #[cfg(not(feature = "local-relay"))]
    let relay_url = None;

    let (server_addr, endpoint) = {
        let _guard = server_span.enter();
        iroh::server_endpoint(&runtime, &relay_url, &opt)
    };

    let endpoint_metrics = endpoint.metrics().clone();

    let server_thread = std::thread::spawn(move || {
        let _guard = server_span.entered();
        if let Err(e) = runtime.block_on(iroh::server(endpoint, opt)) {
            eprintln!("server failed: {e:#}");
        }
    });

    let mut handles = Vec::new();
    for id in 0..opt.clients {
        let server_addr = server_addr.clone();
        let relay_url = relay_url.clone();
        handles.push(std::thread::spawn(move || {
            let _guard = tracing::error_span!("client", id).entered();
            let runtime = rt();
            match runtime.block_on(iroh::client(server_addr, relay_url.clone(), opt)) {
                Ok(stats) => Ok(stats),
                Err(e) => {
                    eprintln!("client failed: {e:#}");
                    Err(e)
                }
            }
        }));
    }

    for (id, handle) in handles.into_iter().enumerate() {
        // We print all stats at the end of the test sequentially to avoid
        // them being garbled due to being printed concurrently
        if let Ok(stats) = handle.join().expect("client thread") {
            stats.print(id);
        }
    }

    if opt.metrics {
        // print metrics
        println!("\nMetrics:");
        collect_and_print("MagicsockMetrics", &*endpoint_metrics.magicsock);
        collect_and_print("RelayClientMetrics", &*endpoint_metrics.relay_client);
        collect_and_print("NetReportMetrics", &*endpoint_metrics.net_report);
        collect_and_print("PortmapMetrics", &*endpoint_metrics.portmapper);
        #[cfg(feature = "local-relay")]
        if let Some(relay_server) = relay_server.as_ref() {
            collect_and_print("RelayServerMetrics", &*relay_server.metrics().server);
        }
    }

    server_thread.join().expect("server thread");

    Ok(())
}

#[cfg(not(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")))]
pub fn run_quinn(opt: Opt) -> Result<()> {
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

    let server_span = tracing::error_span!("server");
    let runtime = rt();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let cert = CertificateDer::from(cert.cert);

    let (server_addr, endpoint) = {
        let _guard = server_span.enter();
        quinn::server_endpoint(&runtime, cert.clone(), key.into(), &opt)
    };

    let server_thread = std::thread::spawn(move || {
        let _guard = server_span.entered();
        if let Err(e) = runtime.block_on(quinn::server(endpoint, opt)) {
            eprintln!("server failed: {e:#}");
        }
    });

    let mut handles = Vec::new();
    for id in 0..opt.clients {
        let cert = cert.clone();
        handles.push(std::thread::spawn(move || {
            let _guard = tracing::error_span!("client", id).entered();
            let runtime = rt();
            match runtime.block_on(quinn::client(server_addr, cert, opt)) {
                Ok(stats) => Ok(stats),
                Err(e) => {
                    eprintln!("client failed: {e:#}");
                    Err(e)
                }
            }
        }));
    }

    for (id, handle) in handles.into_iter().enumerate() {
        // We print all stats at the end of the test sequentially to avoid
        // them being garbled due to being printed concurrently
        if let Ok(stats) = handle.join().expect("client thread") {
            stats.print(id);
        }
    }

    server_thread.join().expect("server thread");

    Ok(())
}

pub fn run_s2n(_opt: s2n::Opt) -> Result<()> {
    unimplemented!()
}

fn collect_and_print(category: &'static str, metrics: &dyn MetricsGroup) {
    let mut map = BTreeMap::new();
    for item in metrics.iter() {
        let value: i64 = match item.value() {
            MetricValue::Counter(v) => v as i64,
            MetricValue::Gauge(v) => v,
            _ => continue,
        };
        map.insert(item.name().to_string(), value);
    }
    println!("{category}: {map:#?}");
}
