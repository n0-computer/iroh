use anyhow::{anyhow, Result};
use fork::{daemon, Fork};
use iroh_util::lock::ProgramLock;
use std::{collections::HashSet, path::PathBuf, process::Command};
use sysinfo::{ProcessExt, SystemExt};

pub struct DaemonDetails {
    pub bin_paths: Vec<PathBuf>,
}

// TODO(b5) - this leaves a stray "iroh start" process running on my machine
// TODO(b5) - have start spin up iroh cloud services for now until iroh-one RPC api is figured out
pub fn start() -> Result<DaemonDetails> {
    // check for any running iroh services
    let locks = existing_daemon_locks()?;
    if locks.contains("iroh-one") {
        return Err(anyhow!("iroh-one is already running"));
    }
    println!("{:?}", locks);

    // ensure iroh-one exists
    let iroh_one_path = which::which("iroh-one")?;

    // start iroh
    if let Ok(Fork::Child) = daemon(false, false) {
        Command::new("iroh-one")
            .output()
            .expect("failed to execute process");
    }

    // TODO - confirm communication with RPC API

    Ok(DaemonDetails {
        bin_paths: vec![iroh_one_path],
    })
}

fn existing_daemon_locks() -> Result<HashSet<&'static str>> {
    let mut locks = HashSet::new();
    let locks = vec!["iroh-one", "iroh-gateway", "iroh-p2p", "iroh-store"]
        .iter()
        .fold(&mut locks, |accum, program| {
            ProgramLock::new(program)
                .unwrap()
                .is_locked()
                .then(|| accum.insert(program.to_owned()));

            accum
        });

    Ok(locks.to_owned())
}

// TODO(b5) - in an ideal world the lock files would contain PIDs of daemon processes
pub fn stop() -> Result<HashSet<&'static str>> {
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
