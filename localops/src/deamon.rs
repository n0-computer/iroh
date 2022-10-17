use anyhow::{anyhow, Ok, Result};
use handlebars::Handlebars;
use serde::Serialize;
use std::fs;
use std::{path::PathBuf, process::Command};
#[cfg(target_os = "linux")]
use users::{get_current_uid, get_user_by_uid};

#[derive(Serialize)]
pub struct Daemon<'a> {
    service_name: &'a str,
    bin_path: Option<PathBuf>,
    data_dir: Option<PathBuf>,
    username: Option<&'a str>,
    description: Option<&'a str>,
}

impl<'a> Daemon<'a> {
    #[cfg(not(target_os = "linux"))]
    pub fn new(service_name: &'a str) -> Self {
        Daemon {
            service_name,
            bin_path: None,
            data_dir: None,
            username: None,
            description: None,
        }
    }

    #[cfg(target_os = "linux")]
    pub fn new(service_name: &'a str) -> Self {
        // let user = get_user_by_uid(get_current_uid()).unwrap();
        // let username: &'a str = user.name().to_str().unwrap();
        let username: &'a str = "ubuntu";
        Daemon {
            service_name,
            bin_path: None,
            data_dir: None,
            username: Some(username),
            description: None,
        }
    }

    pub fn bin_path(&mut self, bin_path: PathBuf) -> &mut Self {
        self.bin_path = Some(bin_path);
        self
    }

    pub fn data_dir(&mut self, data_dir: PathBuf) -> &mut Self {
        self.data_dir = Some(data_dir);
        self
    }

    pub fn description(&mut self, description: &'a str) -> &mut Self {
        self.description = Some(description);
        self
    }

    pub fn install(&mut self) -> Result<()> {
        if self.bin_path == None {
            return Err(anyhow!("binary path must be specified to install"));
        }
        install_daemon(self)
    }

    pub fn remove(&self) -> Result<()> {
        remove_daemon(self)
    }
}

#[cfg(not(target_os = "macos"))]
#[cfg(not(target_os = "linux"))]
#[cfg(not(target_os = "windows"))]
fn install_daemon(deamon: &Daemon) -> Result<()> {
    Err(anyhow!(
        "installing deamons is not supported on your operating system"
    ))
}

#[cfg(not(target_os = "macos"))]
#[cfg(not(target_os = "linux"))]
#[cfg(not(target_os = "windows"))]
fn remove_daemon(deamon: &Daemon) -> Result<()> {
    Err(anyhow!(
        "removing daemons is not supported on your operating system"
    ))
}

#[cfg(target_os = "macos")]
fn install_daemon(daemon: &Daemon) -> Result<()> {
    let home = dirs_next::home_dir()
        .ok_or_else(|| anyhow!("operating environment doesn't provide a home directory"))?;
    let plist_path = home.join(format!(
        "Library/LaunchAgents/computer.iroh.{}.plist",
        daemon.service_name
    ));
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
fn remove_daemon(daemon: &Daemon) -> Result<()> {
    let home = dirs_next::home_dir()
        .ok_or_else(|| anyhow!("operating environment doesn't provide a home directory"))?;
    let plist_path = home.join(format!(
        "Library/LaunchAgents/computer.iroh.{}.plist",
        daemon.service_name
    ));

    if !plist_path.exists() {
        // TODO(b5) - still check with launchd on service status
        return Ok(());
    }

    Command::new("launchctl")
        .arg("unload")
        .arg("-w") // -w marks the job as disabled. job will NOT restart on the next login/restart
        .arg(&plist_path.into_os_string().into_string().unwrap())
        .output()?;

    let plist_path = home.join(format!(
        "Library/LaunchAgents/computer.iroh.{}.plist",
        daemon.service_name
    ));
    fs::remove_file(&plist_path).map_err(|e| {
        anyhow!(format!(
            "error removing file {}: {}",
            plist_path.display(),
            e
        ))
    })?;

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
    let service_path = PathBuf::from(format!(
        "/etc/systemd/system/{}.service",
        daemon.service_name
    ));
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
fn remove_daemon(daemon: &Daemon) -> Result<()> {
    fs::create_dir_all("/some/dir")?;
    let service_path = PathBuf::from(format!(
        "/etc/systemd/system/{}.service",
        daemon.service_name
    ));
    if !service_path.exists() {
        // TODO(b5) - still check with launchd on service status
        return Ok(());
    }
    fs::remove_file(&service_path).map_err(|e| {
        anyhow!(format!(
            "error removing file {}: {}",
            service_path.display(),
            e
        ))
    })?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn install_daemon(daemon: &Daemon) -> Result<()> {
    use std::ffi::OsString;
    use windows_service::{
        service::{ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType},
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;

    let service_binary_path = ::std::env::current_exe()
        .unwrap()
        .with_file_name(format!("{}.exe", daemon.service_name));

    let service_info = ServiceInfo {
        name: OsString::from(deamon.service_name),
        display_name: OsString::from(deamon.service_name),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::OnDemand,
        error_control: ServiceErrorControl::Normal,
        executable_path: service_binary_path,
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None, // run as System
        account_password: None,
    };

    let service = service_manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG)?;
    if daemon.description != None {
        service.set_description(daemon.description)?;
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn remove_daemon(daemon: &Daemon) -> Result<()> {
    use std::{thread, time::Duration};
    use windows_service::{
        service::{ServiceAccess, ServiceState},
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    let manager_access = ServiceManagerAccess::CONNECT;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;

    let service_access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    let service = service_manager.open_service("ping_service", service_access)?;

    let service_status = service.query_status()?;
    if service_status.current_state != ServiceState::Stopped {
        service.stop()?;
        // Wait for service to stop
        thread::sleep(Duration::from_secs(1));
    }

    service.delete()?;
    Ok(())
}
