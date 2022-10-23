use anyhow::{anyhow, Result};
use crossterm::terminal::{Clear, ClearType};
use crossterm::{cursor, style, style::Stylize, QueueableCommand};
use futures::StreamExt;
use iroh_util::iroh_cache_path;
use std::collections::HashSet;
use std::io::{stdout, Write};
use std::time::SystemTime;
use tracing::info;

use iroh_api::{Api, ServiceStatus, StatusRow, StatusTable};
use iroh_util::lock::{LockError, ProgramLock};

const SERVICE_START_TIMEOUT_SECONDS: u64 = 15;

/// start any of {iroh-gateway,iroh-store,iroh-p2p} that aren't currently
/// running.
pub async fn start(api: &impl Api, services: &Vec<String>) -> Result<()> {
    let services = match services.is_empty() {
        true => HashSet::from(["gateway", "store"]),
        false => {
            let mut hs: HashSet<&str> = HashSet::new();
            for s in services {
                hs.insert(s.as_str());
            }
            hs
        }
    };
    start_services(api, services).await
}

// TODO(b5) - should check for configuration mismatch between iroh CLI configuration
// TODO(b5) - services HashSet should be an enum
async fn start_services(api: &impl Api, services: HashSet<&str>) -> Result<()> {
    // check for any running iroh services
    let table = api.check().await;

    let mut missing_services = HashSet::new();
    let missing_services = table
        .iter()
        .fold(&mut missing_services, |accum, status_row| {
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

    // TODO (b5) - use services.difference here, but figure out how to
    // .collect() to &str instead of &&str
    let missing_services: HashSet<&str> = services
        .into_iter()
        .filter(|&service| missing_services.contains(service))
        .collect();

    if missing_services.is_empty() {
        println!(
            "{}",
            "All iroh daemons are already running. all systems nominal.".green()
        );
        return Ok(());
    }

    for service in missing_services.iter() {
        let daemon_name = format!("iroh-{}", service);
        let log_path = iroh_cache_path(format!("iroh-{}.log", service).as_str())?;

        // check if a binary by this name exists
        let bin_path = which::which(&daemon_name).map_err(|_| {
            anyhow!(format!(
                "can't find {} daemon binary on your $PATH. please install {}.\n visit https://iroh.computer/docs/install for more info",
                &daemon_name, &daemon_name
            ))
        })?;

        print!("starting {}... ", &daemon_name.bold());

        iroh_localops::process::daemonize(bin_path, log_path.clone())?;

        let is_up = ensure_status(api, service, iroh_api::ServiceStatus::Serving).await?;
        if is_up {
            println!("{}", "success".green());
        } else {
            eprintln!(
                "{}",
                format!(
                    "error: took more than {}s start.\ncheck log file for details: {}",
                    SERVICE_START_TIMEOUT_SECONDS,
                    log_path.display(),
                )
                .red()
            );
        }
    }

    Ok(())
}

/// stop the default set of services by sending SIGINT to any active daemons
/// identified by lockfiles
pub async fn stop(api: &impl Api, services: &Vec<String>) -> Result<()> {
    let services = match services.is_empty() {
        true => HashSet::from(["store", "p2p", "gateway"]),
        false => {
            let mut hs: HashSet<&str> = HashSet::new();
            for s in services {
                hs.insert(s.as_str());
            }
            hs
        }
    };
    stop_services(api, services).await
}

pub async fn stop_services(api: &impl Api, services: HashSet<&str>) -> Result<()> {
    for service in services {
        let daemon_name = format!("iroh-{}", service);
        info!("checking daemon {} lock", daemon_name);
        let mut lock = ProgramLock::new(&daemon_name)?;
        match lock.active_pid() {
            Ok(pid) => {
                info!("stopping {} pid: {}", daemon_name, pid);
                print!("stopping {}... ", &daemon_name);
                match iroh_localops::process::stop(pid.into()) {
                    Ok(_) => {
                        let is_down = ensure_status(
                            api,
                            service,
                            iroh_api::ServiceStatus::Down(tonic::Status::unavailable(
                                "unavailable",
                            )),
                        )
                        .await?;
                        if is_down {
                            println!("{}", "stopped".red());
                        } else {
                            eprintln!("{}", format!("{} API is still running, but the lock is removed.\nYou may need to manually stop iroh via your operating system", service).red());
                        }
                    }
                    Err(error) => {
                        println!("{}: {}", "error".yellow(), error);
                    }
                }
            }
            Err(e) => match e {
                LockError::NoLock(_) => {
                    eprintln!("{}", format!("{} is already stopped", daemon_name).white());
                }
                LockError::ZombieLock(_) => {
                    lock.destroy_without_checking().unwrap();
                    println!(
                        "stopping {}:, {}",
                        daemon_name,
                        "removed zombie lockfile".red()
                    );
                }
                e => {
                    eprintln!("{} lock error: {}", daemon_name, e);
                    continue;
                }
            },
        }
    }
    Ok(())
}

pub async fn status(api: &impl Api, watch: bool) -> Result<()> {
    let mut stdout = stdout();
    if watch {
        let status_stream = api.watch().await;
        tokio::pin!(status_stream);
        stdout.queue(Clear(ClearType::All))?;
        while let Some(table) = status_stream.next().await {
            stdout
                .queue(cursor::RestorePosition)?
                .queue(Clear(ClearType::FromCursorUp))?
                .queue(cursor::MoveTo(0, 1))?;
            queue_table(&table, &stdout)?;
            stdout
                .queue(cursor::SavePosition)?
                .queue(style::Print("\n"))?
                .flush()?;
        }
        Ok(())
    } else {
        let table = api.check().await;
        queue_table(&table, &stdout)?;
        stdout.flush()?;
        Ok(())
    }
}

/// queues the table for printing
/// you must call `writer.flush()` to execute the queue
pub fn queue_table<W>(table: &StatusTable, mut w: W) -> Result<()>
where
    W: Write,
{
    w.queue(style::PrintStyledContent(
        "Process\t\t\tNumber\tStatus\n".bold(),
    ))?;
    queue_row(&table.gateway, &mut w)?;
    queue_row(&table.p2p, &mut w)?;
    queue_row(&table.store, &mut w)?;
    Ok(())
}

// queue queues this row of the StatusRow to be written
// You must call `writer.flush()` to actually write the content to the writer
pub fn queue_row<W>(row: &StatusRow, w: &mut W) -> Result<()>
where
    W: Write,
{
    w.queue(style::Print(format!("{}\t\t\t", row.name())))?
        .queue(style::Print(format!("{}/1\t", row.number())))?;
    match row.status() {
        ServiceStatus::Unknown => {
            w.queue(style::PrintStyledContent("Unknown".dark_yellow()))?;
        }
        ServiceStatus::NotServing => {
            w.queue(style::PrintStyledContent("Not Serving".dark_yellow()))?;
        }
        ServiceStatus::Serving => {
            w.queue(style::PrintStyledContent("Serving".green()))?;
        }
        ServiceStatus::ServiceUnknown => {
            w.queue(style::PrintStyledContent("Service Unknown".dark_yellow()))?;
        }
        ServiceStatus::Down(status) => match status.code() {
            tonic::Code::Unknown => {
                w.queue(style::PrintStyledContent("Down".dark_yellow()))?
                    .queue(style::Print("\tThe service has been interupted"))?;
            }
            code => {
                w.queue(style::PrintStyledContent("Down".grey()))?
                    .queue(style::Print(format!("\t{}", code)))?;
            }
        },
    };
    w.queue(style::Print("\n"))?;
    Ok(())
}

/// poll until a service matches the desired status. returns Ok(true) if status was matched,
/// and Ok(false) if desired status isn't reported before SERVICE_START_TIMEOUT_SECONDS
async fn ensure_status(
    api: &impl Api,
    service: &str,
    status: iroh_api::ServiceStatus,
) -> Result<bool> {
    let status_stream = api.watch().await;
    tokio::pin!(status_stream);
    let start = SystemTime::now();
    while let Some(table) = status_stream.next().await {
        let is_status = table
            .iter()
            .filter(|row| row.name() == service)
            .map(|row| row.status() == status)
            .next()
            .unwrap();
        if is_status {
            return Ok(true);
        }
        if let Ok(elapsed) = start.elapsed() {
            if elapsed.as_secs() > SERVICE_START_TIMEOUT_SECONDS {
                return Ok(false);
            }
        }
    }
    Err(anyhow!(""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_table_queue() {
        let expect = format!("{}gateway\t\t\t1/1\t{}\np2p\t\t\t1/1\t{}\nstore\t\t\t1/1\t{}\tThe service is currently unavailable\n", "Process\t\t\tNumber\tStatus\n".bold(), "Unknown".dark_yellow(), "Serving".green(), "Down".grey());
        let table = StatusTable::new(
            Some(StatusRow::new("gateway", 1, ServiceStatus::Unknown)),
            Some(StatusRow::new("p2p", 1, ServiceStatus::Serving)),
            Some(StatusRow::new(
                "store",
                1,
                ServiceStatus::Down(tonic::Status::new(tonic::Code::Unavailable, "")),
            )),
        );

        let mut got = Vec::new();
        queue_table(&table, &mut got).unwrap();
        got.flush().unwrap();
        let got = String::from_utf8(got).unwrap();
        assert_eq!(expect, got);
    }

    #[test]
    fn status_row_queue() {
        struct TestCase {
            row: StatusRow,
            output: String,
        }

        let rows = vec![
            TestCase {
                row: StatusRow::new("test", 1, ServiceStatus::Unknown),
                output: format!("test\t\t\t1/1\t{}\n", "Unknown".dark_yellow()),
            },
            TestCase {
                row: StatusRow::new("test", 1, ServiceStatus::NotServing),
                output: format!("test\t\t\t1/1\t{}\n", "Not Serving".dark_yellow()),
            },
            TestCase {
                row: StatusRow::new("test", 1, ServiceStatus::Serving),
                output: format!("test\t\t\t1/1\t{}\n", "Serving".green()),
            },
            TestCase {
                row: StatusRow::new("test", 1, ServiceStatus::ServiceUnknown),
                output: format!("test\t\t\t1/1\t{}\n", "Service Unknown".dark_yellow()),
            },
            TestCase {
                row: StatusRow::new(
                    "test",
                    1,
                    ServiceStatus::Down(tonic::Status::new(tonic::Code::Unknown, "unknown")),
                ),
                output: format!(
                    "test\t\t\t1/1\t{}\tThe service has been interupted\n",
                    "Down".dark_yellow()
                ),
            },
            TestCase {
                row: StatusRow::new(
                    "test",
                    1,
                    ServiceStatus::Down(tonic::Status::new(
                        tonic::Code::Unavailable,
                        "message text",
                    )),
                ),
                output: format!(
                    "test\t\t\t1/1\t{}\tThe service is currently unavailable\n",
                    "Down".grey()
                ),
            },
        ];

        for row in rows.into_iter() {
            let mut got = Vec::new();
            queue_row(&row.row, &mut got).unwrap();
            got.flush().unwrap();
            let got = String::from_utf8(got).unwrap();
            assert_eq!(row.output, got);
        }
    }
}
