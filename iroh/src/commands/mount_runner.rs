// Based on https://github.com/xetdata/xet-core/blob/main/rust/gitxetcore/src/xetmnt/mod.rs

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, bail, Result};
use nfsserve::tcp::{NFSTcp, NFSTcpListener};
use nfsserve::vfs::NFSFileSystem;
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::time;
use tracing::{error, info};

pub fn check_for_mount_program() -> bool {
    if cfg!(target_os = "macos") {
        // we can always mount on mac
        true
    } else if cfg!(target_os = "linux") {
        // we use /sbin/mount.nfs on Linux
        // TODO: the command here is only for Ubuntu. Might need to check
        // for the other OSes
        if !Path::new("/sbin/mount.nfs").exists() {
            error!("Unable to locate /sbin/mount.nfs");
            error!("Ubuntu: Install the nfs client package with 'apt install nfs-common'");
            error!("Redhat/Fedora: Install the nfs client package with 'yum install nfs-utils'");
            false
        } else {
            true
        }
    } else if cfg!(target_os = "windows") {
        // TODO: must change this to deteck if the NFS Client is installed.  I don't see how to do this
        // until mounting fails (with an obtuse error message).   For now, just assume it works so
        // we can get on to testing this.
        true
    } else {
        error!("Unsupported");
        false
    }
}

/// Constructs the mac mount command
fn build_mac_mount_command(ip: String, hostport: u16, mount_path: &str, writable: bool) -> Command {
    let mut ret = Command::new("/sbin/mount");
    ret.arg("-t").arg("nfs");
    if writable {
        ret.arg("-o").arg(format!(
            "nolocks,vers=3,tcp,rsize=131072,wsize=1048576,actimeo=120,port={hostport},mountport={hostport}"
        ));
    } else {
        ret.arg("-o").arg(format!(
            "rdonly,nolocks,vers=3,tcp,rsize=131072,actimeo=120,port={hostport},mountport={hostport}"
        ));
    }

    ret.arg(format!("{}:/", &ip)).arg(mount_path);
    ret
}

fn build_windows_mount_command(
    ip: String,
    hostport: u16,
    mount_drive: String,
    writable: bool,
) -> Result<Command> {
    debug_assert_eq!(mount_drive.len(), 1);
    debug_assert_eq!(mount_drive, mount_drive.to_uppercase());

    if hostport != 111 {
        bail!("NFS mount port must be 111 on windows.");
    }

    //    let IP = windows_
    let mut ret: Command = Command::new("mount.exe");
    info!(
        "Forming mount command with IP = {:?}, port = {:?}",
        &ip, &hostport
    );

    ret.args([
        "-o",
        &format!(
            // Note: rsize + wsize are in kb.
            "anon,nolock,mtype=soft,fileaccess={},casesensitive,lang=ansi,rsize=128,wsize=128,timeout=60,retry=2",
            if writable { "6" } else { "4" }
        ),
        &format!("\\\\{ip}\\\\"),
        &format!("{}:", &mount_drive),
    ]);

    Ok(ret)
}

/// Constructs the linux mount command
fn build_linux_mount_command(
    ip: String,
    hostport: u16,
    mount_path: String,
    writable: bool,
    sudo: bool,
) -> Command {
    let mut ret = if sudo {
        let mut sudocmd = Command::new("sudo");
        sudocmd.arg("mount.nfs");
        sudocmd
    } else {
        Command::new("mount.nfs")
    };
    if writable {
        ret.arg("-o")
        .arg(format!(
            "user,noacl,nolock,vers=3,tcp,wsize=1048576,rsize=131072,actimeo=120,port={hostport},mountport={hostport}"
        ));
    } else {
        ret.arg("-o").arg(format!(
            "user,noacl,nolock,vers=3,tcp,rsize=131072,actimeo=120,port={hostport},mountport={hostport}"
        ));
    }
    ret.arg(format!("{}:/", &ip)).arg(mount_path);
    ret
}

/// Handle the mount command result
fn handle_mount_command_output(
    cmd: &Command,
    output: std::io::Result<std::process::ExitStatus>,
) -> Result<()> {
    match output {
        Err(e) => {
            bail!("Failed to run mount command.{cmd:?}. Error {e:?}");
        }
        Ok(v) => {
            if !v.success() {
                bail!("Mount command {cmd:?} failed with {v:?}");
            }
        }
    }
    Ok(())
}

/// Runs the mount command for every platform
async fn perform_mount(
    ip: String,
    hostport: u16,
    mount_path: String,
    writable: bool,
) -> Result<()> {
    if cfg!(target_os = "macos") {
        let mount_task = tokio::spawn(async move {
            let mut cmd = build_mac_mount_command(ip, hostport, &mount_path, writable);
            info!("Running command {:?}", cmd);
            let output = cmd.status().await;
            handle_mount_command_output(&cmd, output)
        });
        mount_task
            .await
            .map_err(|je| anyhow!("Error spawning mount process task: {:?}", &je))??;
    } else if cfg!(target_os = "linux") {
        let mpath = mount_path.clone();
        let ip_ = ip.clone();
        let mount_task = tokio::spawn(async move {
            let mut cmd = build_linux_mount_command(ip_, hostport, mpath, writable, false);
            info!("Running command {:?}", cmd);
            let output = cmd.status().await;
            handle_mount_command_output(&cmd, output)
        });
        let resp = mount_task.await;
        if resp.is_err() || resp.unwrap().is_err() {
            error!("Failed to mount. Retrying as root with sudo...");
        } else {
            return Ok(());
        }

        // retry with sudo
        let mount_task = tokio::spawn(async move {
            let mut cmd = build_linux_mount_command(ip, hostport, mount_path, writable, true);
            info!("Running command {:?}", cmd);
            let output = cmd.status().await;
            handle_mount_command_output(&cmd, output)
        });
        let resp = mount_task.await;
        // this time we return all errors
        let mount_result = resp.map_err(|e| anyhow!("Error spawning mount process task: {e:?}"))?;
        if mount_result.is_err() {
            return mount_result;
        } else {
            eprintln!("Mount command successful as root");
            return Ok(());
        }
    } else if cfg!(target_os = "windows") {
        let mount_task = tokio::spawn(async move {
            let mut cmd = build_windows_mount_command(ip, hostport, mount_path, writable)?;
            info!("Running command {:?}", cmd);
            let output = cmd.status().await;
            handle_mount_command_output(&cmd, output)
        });
        mount_task
            .await
            .map_err(|e| anyhow!("Error spawning mount process task: {e:?}"))??;
    }

    Ok(())
}

/// runs mount | grep path
/// if anything matches, mount is still running.
/// Return false if mount is missing. And true otherwise.
#[cfg(not(target_os = "windows"))]
async fn poll_for_mount_existence(path_to_search: &str) -> bool {
    let mountoutput = Command::new("mount").output().await;
    if mountoutput.is_err() {
        info!("Unable to poll mount command");
        return true;
    }
    let mountoutput = mountoutput.unwrap();
    if !mountoutput.status.success() {
        info!("Unable to poll mount command");
        return true;
    }
    let stdout = String::from_utf8_lossy(&mountoutput.stdout);
    stdout.contains(path_to_search)
}

/// runs mount | grep path
/// if anything matches, mount is still running.
/// Return false if mount is missing. And true otherwise.
///
/// NOTE: we do need to make sure we handle this correctly..  mount on windows
/// hangs indefinitely if any of the mountpoints is still active, but the server is inaccessible.  
/// This shouldn't be a problem, but it is definitely something to be aware of.
#[cfg(target_os = "windows")]
async fn poll_for_mount_existence(path_to_search: &str) -> bool {
    debug_assert_eq!(path_to_search.len(), 1);
    debug_assert_eq!(path_to_search.to_uppercase(), path_to_search);

    let mountoutput = Command::new("mount").output().await;
    if mountoutput.is_err() {
        info!("Unable to poll mount command");
        return true;
    }
    let mountoutput = mountoutput.unwrap();
    if !mountoutput.status.success() {
        info!("Unable to poll mount command");
        return true;
    }
    let stdout = String::from_utf8_lossy(&mountoutput.stdout);
    for line in stdout.lines() {
        if line.starts_with(path_to_search) {
            return true;
        }
    }
    false
}

#[allow(clippy::too_many_arguments)]
pub async fn perform_mount_and_wait_for_ctrlc<F: NFSFileSystem + 'static + Send>(
    mount: &Path,
    fs: F,
    autostop_on_unmount: bool,
    writable: bool,
    ip_address: String,
    mount_ready_callback: impl FnOnce(),
) -> Result<()> {
    // we remember if the mount path was created so that we can delete
    // it when we unmount
    let mut mount_path_was_created = false;
    let mount_path: String = {
        #[cfg(target_os = "windows")]
        {
            let mount_drive = mount.to_str().unwrap().to_uppercase();
            let mount_drive = mount_drive.strip_prefix("\"").unwrap_or(&mount_drive);
            let mount_drive = mount_drive.strip_suffix("\"").unwrap_or(&mount_drive);
            let mount_drive = mount_drive.strip_suffix("/").unwrap_or(&mount_drive);

            // Make sure mount path is a drive letter
            let mount_drive = mount_drive.strip_suffix(":").unwrap_or(&mount_drive);

            // validate the mountpoint is just a single letter.
            if mount_drive.len() != 1 {
                bail!("Currently the mount path on windows repos must be an unused drive letter (got {:?})", mount_drive);
            }

            mount_drive.to_owned()
        }

        #[cfg(not(target_os = "windows"))]
        {
            // validate mount point exists
            if !mount.exists() {
                if let Err(e) = tokio::fs::create_dir_all(mount).await {
                    error!("Unable to create directory {:?}. Error: {:?}", mount, e);
                    return Ok(());
                }
                mount_path_was_created = true;
            }
            // validate mount point is empty
            assert!(mount.exists());

            let is_empty = mount.read_dir().unwrap().next().is_none();
            if !is_empty {
                bail!("Directory {mount:?} is not empty");
            }

            mount.to_str().unwrap().to_owned()
        }
    };

    let ip = {
        #[cfg(not(target_os = "windows"))]
        {
            if ip_address.contains(':') {
                ip_address
            } else {
                ip_address + ":0"
            }
        }

        #[cfg(target_os = "windows")]
        {
            // Strip out possible correct port specifications
            let ip_address = ip_address
                .strip_suffix(":111")
                .unwrap_or(&ip_address)
                .to_owned();

            if ip_address.contains(":") {
                return Err(GitXetRepoError::InvalidOperation(format!(
                    "Port number is fixed in Windows."
                )));
            }
            ip_address + ":111"
        }
    };

    // load the xet
    let mut listener = NFSTcpListener::bind(&ip, fs).await?;

    // start listening
    let hostport = listener.get_listen_port();
    let ip = listener.get_listen_ip().to_string();
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<bool>(1);
    if autostop_on_unmount {
        #[cfg(unix)]
        listener.set_mount_listener(shutdown_tx.clone());
    }

    // This is the main task handling loop.
    // It polls on 3 things
    // 1. The NFS server
    // 2. a shutdown signal
    // 3. A poll every 5 seconds checking the output of the mount command
    const MOUNT_POLL_INTERVAL_MS: u64 = 15000;

    let mount_poll_path = mount_path.clone();
    let mount_started = Arc::new(AtomicBool::new(false));
    let mount_started_poll = mount_started.clone();
    // spawn the handler into a separate task
    let handle_task = tokio::spawn(async move {
        let mut keep_running = true;
        while keep_running {
            // Sleep select implementation from
            // https://docs.rs/tokio/latest/tokio/time/struct.Sleep.html
            let sleep = time::sleep(time::Duration::from_millis(MOUNT_POLL_INTERVAL_MS));
            tokio::pin!(sleep);

            tokio::select! {
                res = listener.handle_forever() => {
                    error!("Server Error {:?}", res);
                    res.unwrap();
                }
                r = shutdown_rx.recv() => {
                    keep_running = r.unwrap_or(false);
                    if !keep_running {
                        info!("Shutting down");
                        // try to delete the folder
                        if mount_path_was_created {
                            #[cfg(not(target_os = "windows"))]
                            let _ = std::fs::remove_dir(&mount_poll_path);
                        }
                    }
                }
                () = &mut sleep => {
                    // we start polling for mount existence only once the mount actually starts
                    if mount_started_poll.load(Ordering::Relaxed) {
                        info!("Polling for mount existence");
                        if !poll_for_mount_existence(&mount_poll_path).await {
                            info!("Shutting down");
                            keep_running = false;
                        }
                    }
                    sleep.as_mut().reset(time::Instant::now() + time::Duration::from_millis(MOUNT_POLL_INTERVAL_MS));
                }
            }
        }
    });

    // actually perform the mount
    perform_mount(ip, hostport, mount_path.clone(), writable).await?;

    // this is necessary due to some silliness with FnMut
    // Ex: https://github.com/rustwasm/wasm-bindgen/issues/1269
    let mut wrapped_shutdown_tx = Some(shutdown_tx);
    // if mount is good, we set a ctrl-c handler which runs umount
    ctrlc::set_handler(move || {
        eprintln!("Ctrl-C received. Unmounting.");
        let output = std::process::Command::new("umount")
            .arg(&mount_path)
            .status();
        match output {
            Err(e) => {
                error!("Failed to unmount: {:?}", e);
                error!(
                    "You will need to unmount manually with \'umount -f {:?}\'",
                    mount_path
                );
            }
            Ok(v) => {
                if !v.success() {
                    error!("Failed to unmount");
                    error!(
                        "You will need to unmount manually with \'umount -f {:?}\'",
                        mount_path
                    );
                }
            }
        }

        let _ = wrapped_shutdown_tx.take().unwrap().blocking_send(false);
    })
    .expect("Error setting Ctrl-C handler");

    // This will hang forever
    if autostop_on_unmount {
        eprintln!("Mount at {mount:?} successful. Unmount with \'umount {mount:?}\'");
    } else {
        eprintln!("Mount at {mount:?} successful. Hit Ctrl-C to unmount");
    }
    mount_ready_callback();
    // start the mount polling
    mount_started.store(true, Ordering::Relaxed);
    handle_task.await.unwrap();
    Ok(())
}
