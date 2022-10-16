use handlebars::Handlebars;
use std::fs;
use serde::Serialize;
use anyhow::{anyhow, Result, Ok};
use std::{path::PathBuf, process::Command};
#[cfg(target_os = "linux")]
use users::{get_user_by_uid, get_current_uid};

#[derive(Serialize)]
pub struct Daemon<'a> {
  service_name: &'a str,
  bin_path: Option<PathBuf>,
  data_dir: Option<PathBuf>,
  username: Option<&'a str>,
}

impl<'a> Daemon<'a> {
  pub fn new(service_name: &'a str) -> Self {
    Daemon{
      service_name,
      bin_path: None,
      data_dir: None,
      username: None
    }
  }

  pub fn binary_path(&mut self, bin_path: PathBuf) -> &mut Self {
    self.bin_path = Some(bin_path);
    self
  }

  pub fn data_dir(&mut self, data_dir: PathBuf) -> &mut Self {
    self.data_dir = Some(data_dir);
    self
  }

  pub fn install(&self) -> Result<()> {
    if self.bin_path == None {
      return Err(anyhow!("binary path must be specified to install"));
    }
    install_daemon(self)
  }

  pub fn remove(&self) -> Result<()> {
    remove_deamon(self)
  }
}

#[cfg(not(target_os = "macos"))]
#[cfg(not(target_os = "linux"))]
fn install_daemon(deamon: &Daemon) -> Result<()> {
  Err(anyhow!("installing deamons is not supported on your operating system"))
}

#[cfg(not(target_os = "macos"))]
#[cfg(not(target_os = "linux"))]
fn remove_deamon(deamon: &Daemon) -> Result<()> {
  Err(anyhow!("removing daemons is not supported on your operating system"))
}

#[cfg(target_os = "macos")]
fn install_daemon(daemon: &Daemon) -> Result<()> {
    let home = dirs_next::home_dir()
        .ok_or_else(|| anyhow!("operating environment doesn't provide a home directory"))?;
    let plist_path = home.join(format!("Library/LaunchAgents/computer.iroh.{}.plist", daemon.service_name));
    let rendered = Handlebars::new().render_template(LAUNCHD_JOB_TEMPLATE, daemon)?;
    fs::write(&plist_path, rendered)?;

    Command::new("launchctl")
        .arg("load")
        .arg("-w") // -w marks the job as "not disabled", WILL survive restarts
        .arg(&plist_path.into_os_string().into_string().unwrap())
        .output()?;

    Ok(())
}

#[cfg(target_os = "macos")]
fn remove_deamon(daemon: &Daemon) -> Result<()> {
    let home = dirs_next::home_dir()
        .ok_or_else(|| anyhow!("operating environment doesn't provide a home directory"))?;
    let plist_path = home.join(format!("Library/LaunchAgents/computer.iroh.{}.plist", daemon.service_name));


    if !plist_path.exists() {
      // TODO(b5) - still check with launchd on service status
      return Ok(());
    }

    Command::new("launchctl")
        .arg("unload")
        .arg("-w") // -w marks the job as disabled. job will NOT restart on the next login/restart
        .arg(&plist_path.into_os_string().into_string().unwrap())
        .output()?;

    let plist_path = home.join(format!("Library/LaunchAgents/computer.iroh.{}.plist", daemon.service_name));
    fs::remove_file(&plist_path).map_err(|e| anyhow!(format!("error removing file {}: {}", plist_path.display(), e)))?;

    Ok(())
}

#[cfg(target_os = "macos")]
const LAUNCHD_JOB_TEMPLATE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>computer.iroh.{{ service_name }}.plist</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>{{ data_dir }}/{{ service_name }}.err</string>
    <key>StandardOutPath</key>
    <string>{{ data_dir }}/{{ service_name }}.out</string>
    <key>ProgramArguments</key>
    <array>
      <string>{{ bin_path }}</string>
    </array>
  </dict>
</plist>
"#;


#[cfg(target_os = "linux")]
fn install_daemon(daemon: &Daemon) -> Result<()> {
  let user = get_user_by_uid(get_current_uid())?;
  daemon.username = user.name().to_string_lossy();
  let service_path = PathBuf::new(format!("/etc/systemd/system/{}.service", daemon.service_name));
  let rendered = Handlebars::new().render_template(SYSTEMD_SERVICE_TEMPLATE, daemon)?;
  fs::write(&service_path, rendered)?;
  Ok(())
}

#[cfg(target_os = "linux")]
const SYSTEMD_SERVICE_TEMPLATE: &str = "[Unit]
Description={{ service_name }}
After=network.target
StartLimitIntervalSec=0[Service]
Type=simple
Restart=always
RestartSec=3
User={{ username }}
ExecStart=/usr/bin/env {{ bin_path }}

[Install]
WantedBy=multi-user.target";

#[cfg(target_os = "linux")]
fn remove_daemon(deamon: &Daemon) -> Result<()> {
  let service_path = PathBuf::new(format!("/etc/systemd/system/{}.service", daemon.service_name));
  if !service_path.exists() {
    // TODO(b5) - still check with launchd on service status
    return Ok(());
  }
  fs::remove_file(&service_path).map_err(|e| anyhow!(format!("error removing file {}: {}", service_path.display(), e)))?;
}
