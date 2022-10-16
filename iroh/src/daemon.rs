use anyhow::{anyhow, Result};
use iroh_api::Api;
use std::{collections::HashSet, path::PathBuf};
use localops::deamon::Daemon;

pub struct DaemonDetails {
    pub bin_paths: Vec<PathBuf>,
}

/// start registers iroh with the host operating system, configuring iroh as a
/// service that will be kept in the event of a crash by the OS.
/// Current supported platforms:
///   - MacOS using launchd
/// terms:
/// daemon - a binary that when running, supplies one or more services. currently {iroh-one,iroh-gateway,iroh-p2p,iroh-store}
/// service - an RPC endpoint. currently one of {gateway,p2p,store}
/// one deamon can provide multiple services
///
/// TODO(b5) - start should check for configuration mismatch between iroh CLI configuration
/// any daemons services it's starting
pub async fn start(api: &impl Api) -> Result<DaemonDetails> {
    start_services(api, HashSet::from(["store", "p2p", "gateway"])).await
}

async fn start_services(api: &impl Api, services: HashSet<&str>) -> Result<DaemonDetails> {
    // check for any running iroh services
    let table = api.check().await;

    let mut missing_services = HashSet::new();
    let missing_services = table.fold(&mut missing_services, |accum, status_row| {
        match status_row.status() {
            iroh_api::ServiceStatus::Serving => (),
            iroh_api::ServiceStatus::Unknown => {
                accum.insert(status_row.name());
            }
            iroh_api::ServiceStatus::NotServing => {
                accum.insert(status_row.name());
            }
            iroh_api::ServiceStatus::ServiceUnknown => (),
            iroh_api::ServiceStatus::Down(_reason) => {
                accum.insert(status_row.name());
                // TODO(b5) - warn user that a service is down & exit
            }
        }
        accum
    });

    // construct a new set from the intersection of missing & expected services
    let missing_services: HashSet<&str> = services
        .into_iter()
        .filter(|&service| missing_services.contains(service))
        .collect();

    if missing_services.is_empty() {
        return Err(anyhow!("iroh is already running. all systems nominal."));
    }

    for &service in missing_services.iter() {
      let data_dir = iroh_util::iroh_data_root()?;
        let daemon_name = format!("iroh-{}", service);

        // check if a binary by this name exists
        let bin_path = which::which(&daemon_name).map_err(|_| {
            anyhow!(format!(
                "can't find {} binary on your $PATH. please install {}",
                daemon_name, daemon_name
            ))
        })?;

        println!("starting {}", daemon_name);
        Daemon::new(service)
          .binary_path(bin_path)
          .data_dir(data_dir)
          .install()?;

        println!("{} daemon registered with operating system", service);
    }

    // TODO - confirm communication with RPC API

    // TODO(b5) - properly collect started daemons
    Ok(DaemonDetails { bin_paths: vec![] })
}

// TODO(b5) - in an ideal world the lock files would contain PIDs of daemon processes
pub fn stop() -> Result<()> {
    for service_name in ["one", "gateway", "p2p", "store"] {
        Daemon::new(service_name)
          .remove()
          .unwrap_or_else(|e| {
            println!("error removing {} service:\n {}", service_name, e);
          })
    }
    Ok(())
}

