#![allow(deprecated)]

use std::collections::BTreeMap;

use anyhow::Result;
use clap::Parser;
#[cfg(not(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")))]
use iroh_net_bench::quinn;
use iroh_net_bench::{configure_tracing_subscriber, iroh, rt, s2n, Commands, Opt};

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
    if opt.metrics {
        // enable recording metrics
        iroh_metrics::core::Core::try_init(|reg, metrics| {
            use iroh_metrics::core::Metric;
            metrics.insert(iroh_net::metrics::MagicsockMetrics::new(reg));
            metrics.insert(iroh_net::metrics::NetcheckMetrics::new(reg));
            metrics.insert(iroh_net::metrics::PortmapMetrics::new(reg));
            #[cfg(feature = "local-relay")]
            if opt.with_relay {
                metrics.insert(iroh_net::metrics::RelayMetrics::new(reg));
            }
        })?;
    }

    #[cfg(not(feature = "local-relay"))]
    if opt.with_relay {
        anyhow::bail!(
            "Must compile the benchmark with the `local-relay` feature flag to use this option"
        );
    }

    let server_span = tracing::error_span!("server");
    let runtime = rt();

    #[cfg(feature = "local-relay")]
    let (relay_url, _guard) = if opt.with_relay {
        let (_, relay_url, _guard) = runtime.block_on(iroh_net::test_utils::run_relay_server())?;

        (Some(relay_url), Some(_guard))
    } else {
        (None, None)
    };
    #[cfg(not(feature = "local-relay"))]
    let relay_url = None;

    let (server_addr, endpoint) = {
        let _guard = server_span.enter();
        iroh::server_endpoint(&runtime, &relay_url, &opt)
    };

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
        let core =
            iroh_metrics::core::Core::get().ok_or_else(|| anyhow::anyhow!("Missing metrics"))?;
        println!("\nMetrics:");
        collect_and_print(
            "MagicsockMetrics",
            core.get_collector::<iroh_net::metrics::MagicsockMetrics>(),
        );
        collect_and_print(
            "NetcheckMetrics",
            core.get_collector::<iroh_net::metrics::NetcheckMetrics>(),
        );
        collect_and_print(
            "PortmapMetrics",
            core.get_collector::<iroh_net::metrics::PortmapMetrics>(),
        );
        // if None, (this is the case if opt.with_relay is false), then this is skipped internally:
        #[cfg(feature = "local-relay")]
        collect_and_print(
            "RelayMetrics",
            core.get_collector::<iroh_net::metrics::RelayMetrics>(),
        );
    }

    server_thread.join().expect("server thread");

    Ok(())
}

#[cfg(not(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")))]
pub fn run_quinn(opt: Opt) -> Result<()> {
    let server_span = tracing::error_span!("server");
    let runtime = rt();
    let (server_addr, endpoint) = {
        let _guard = server_span.enter();
        quinn::server_endpoint(&runtime, &opt)
    };

    let server_thread = std::thread::spawn(move || {
        let _guard = server_span.entered();
        if let Err(e) = runtime.block_on(quinn::server(endpoint, opt)) {
            eprintln!("server failed: {e:#}");
        }
    });

    let mut handles = Vec::new();
    for id in 0..opt.clients {
        handles.push(std::thread::spawn(move || {
            let _guard = tracing::error_span!("client", id).entered();
            let runtime = rt();
            match runtime.block_on(quinn::client(server_addr, opt)) {
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

fn collect_and_print(
    category: &'static str,
    metrics: Option<&impl iroh_metrics::struct_iterable::Iterable>,
) {
    let Some(metrics) = metrics else {
        return;
    };
    let mut map = BTreeMap::new();
    for (name, counter) in metrics.iter() {
        if let Some(counter) = counter.downcast_ref::<iroh_metrics::core::Counter>() {
            map.insert(name.to_string(), counter.get());
        }
    }
    println!("{category}: {map:#?}");
}
