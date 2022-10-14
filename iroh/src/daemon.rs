use anyhow::{anyhow, Result};
use fork::{daemon, Fork};
use iroh_util::lock::ProgramLock;
use std::{collections::HashSet, path::PathBuf, process::Command};
use sysinfo::{ProcessExt, SystemExt};
use iroh_api::Api;

pub struct DaemonDetails {
    pub bin_paths: Vec<PathBuf>,
}

// TODO(b5) - this leaves a stray "iroh start" process running on my machine
// TODO(b5) - have start spin up iroh cloud services for now until iroh-one RPC api is figured out
//
/// start ensures each service passed in the services set is reachable, starting
/// deamons that provide services if not
/// terms:
/// daemon - a binary that when running, supplies one or more services. currently {iroh-one,iroh-gateway,iroh-p2p,iroh-store}
/// service - an RPC endpoint. currently one of {gateway,p2p,store}
/// one deamon can provide multiple services
/// 
/// TODO(b5) - start should check for configuration mismatch between iroh CLI configuration
/// any daemons services it's starting
pub async fn start(api: &impl Api) -> Result<DaemonDetails> {
    start_services(api, HashSet::from([
      "store",
      "p2p",
      "gateway",
    ])).await
}

async fn start_services(api: &impl Api, services: HashSet<&str>) -> Result<DaemonDetails> {
  // check for any running iroh services
  let table = api.check().await;

  let mut missing_services = HashSet::new();
  let missing_services = table.fold(&mut missing_services, |accum, statusRow|{
    match statusRow.status() {
      iroh_api::ServiceStatus::Serving => (),
      iroh_api::ServiceStatus::Unknown => { accum.insert(statusRow.name()); },
      iroh_api::ServiceStatus::NotServing => { accum.insert(statusRow.name()); },
      iroh_api::ServiceStatus::ServiceUnknown => (),
      iroh_api::ServiceStatus::Down(_reason) => {
        accum.insert(statusRow.name());
        // TODO(b5) - warn user that a service is down & exit
      },
    }
    accum
  });
  
  if missing_services.len() == 0 {
    return Err(anyhow!("iroh is running. all systems nominal."));
  }

  for &service in missing_services.iter() {
    let daemon_name = format!("iroh-{}", service);

    // TODO(b5) - once iroh cloud services use locks, check their lock presence first
    // if a lock exists that means a service is likely already trying to run
    // ProgramLock::new(program)
    //     .unwrap()
    //     .is_locked()
    //     .then(|| accum.insert(program.to_owned()));

    // check if a binary by this name exists
    let daemon_path = which::which(&daemon_name).map_err(|e| anyhow!(format!("can't find {} binary on your $PATH. please install {}", daemon_name, daemon_name)))?;

    //
    if let Ok(Fork::Child) = daemon(false, false) {
      Command::new(daemon_path)
          .output()
          .expect("failed to execute process");
    }
  }

  // let locks = existing_daemon_locks()?;
  // if locks.contains("iroh-one") {
  //     return Err(anyhow!("iroh-one is already running"));
  // }

  // ensure iroh-one exists
  // let iroh_one_path = which::which("iroh-one")?;

  // start iroh

  // TODO - confirm communication with RPC API

  // TODO(b5) - properly collect started daemons
  Ok(DaemonDetails {
      bin_paths: vec![],
  })
}

// TODO(b5) - in an ideal world the lock files would contain PIDs of daemon processes
pub fn stop() -> Result<HashSet<&'static str>> {
    // TODO(b5) - iroh stop should also check & forcibly clear any extraneous lock files

    let mut system = sysinfo::System::new();
    system.refresh_all();

    let mut locks = HashSet::new();
    let locks = vec!["iroh-one", "iroh-gateway", "iroh-p2p", "iroh-store"]
        .iter()
        .fold(&mut locks, |accum, program| {
            for p in system.processes_by_name(program) {
                println!("stopping process {} with pid {}", p.name(), p.pid());
                let mut kill = Command::new("kill")
                    .args(["-s", "SIGKILL", p.pid().to_string().as_str()])
                    .spawn()
                    .unwrap();

                kill.wait().unwrap();
            }

            accum
        });

    Ok(locks.to_owned())
}
