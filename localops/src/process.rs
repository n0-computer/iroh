use std::path::PathBuf;
use std::process::Command;

use anyhow::{anyhow, Result};
#[cfg(any(target_os = "macos", target_os = "linux"))]
use nix::sys::signal::{kill, Signal};
#[cfg(any(target_os = "macos", target_os = "linux"))]
use nix::unistd::Pid;

pub fn daemonize(bin_path: PathBuf) -> Result<()> {
    daemonize_process(bin_path)
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn daemonize_process(bin_path: PathBuf) -> Result<()> {
    Err(anyhow!(
        "stopping processes is not supported on your operating system"
    ))
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn daemonize_process(bin_path: PathBuf) -> Result<()> {
    let status = Command::new("bash")
        .arg("-c")
        .arg(format!("{} &", bin_path.to_str().unwrap()))
        .status()?;

    if !status.success() {
        Err(anyhow::anyhow!("cargo build failed"))?;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn daemonize_process(bin_path: PathBuf) -> Result<()> {
    Err(anyhow!("stopping processes on windows is not supported"))
}

pub fn stop(pid: u32) -> Result<()> {
    stop_process(pid)
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn stop_process(pid: u32) -> Result<()> {
    Err(anyhow!(
        "stopping processes is not supported on your operating system"
    ))
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn stop_process(pid: u32) -> Result<()> {
    let id = Pid::from_raw(pid.try_into()?);
    kill(id, Signal::SIGKILL).map_err(|e| anyhow!("killing process, error number: {}", e))
}

#[cfg(target_os = "windows")]
fn stop_process(pid: u32) -> Result<()> {
    Err(anyhow!("stopping processes on windows is not supported"))
}
