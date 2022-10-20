use anyhow::{anyhow, Result};
use crossterm::terminal::{Clear, ClearType};
use crossterm::{cursor, style, style::Stylize, QueueableCommand};
use futures::StreamExt;
use iroh_util::iroh_cache_path;
use std::collections::HashSet;
use std::io::{stdout, Write};
use tracing::info;

use iroh_api::{Api, ServiceStatus, StatusRow, StatusTable};
use iroh_util::lock::{read_lock_pid, try_cleanup_dead_lock, LockError, ProgramLock};

/// start any of {iroh-gateway,iroh-store,iroh-p2p} that aren't currently
/// running.
pub async fn start(api: &impl Api) -> Result<()> {
    // start_services(api, HashSet::from(["store"])).await
    start_services(api, HashSet::from(["store", "p2p", "gateway"])).await
}

// TODO(b5) - should check for configuration mismatch between iroh CLI configuration
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

    // construct a new set from the intersection of missing & expected services
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

    for &service in missing_services.iter() {
        // let data_dir = iroh_util::iroh_data_root()?;
        let daemon_name = format!("iroh-{}", service);
        let log_path = iroh_cache_path(format!("iroh-{}.log", service).as_str())?;

        // // check if a binary by this name exists
        let bin_path = which::which(&daemon_name).map_err(|_| {
            anyhow!(format!(
                "can't find {} daemon binary on your $PATH. please install {}.\n visit https://iroh.computer/docs/install for more info",
                &daemon_name, &daemon_name
            ))
        })?;

        print!("starting {}... ", &daemon_name.bold());
        iroh_localops::process::daemonize(bin_path, log_path)?;
        println!("{}", "success".green());
        // TODO - confirm communication with RPC API
    }

    Ok(())
}

///
pub async fn stop() -> Result<()> {
    for daemon_name in ["iroh-one", "iroh-gateway", "iroh-p2p", "iroh-store"] {
        info!("checking daemon {} lock", daemon_name);
        let lock = ProgramLock::new(daemon_name)?;
        if lock.is_locked() {
            let pid = match read_lock_pid(daemon_name) {
                Ok(pid) => pid,
                Err(error) => match error {
                    LockError::CorruptLock(path) => {
                        println!("removing corrupted lockfile for {} daemon", daemon_name);
                        std::fs::remove_file(path).map_err(|e| anyhow!("{}", e))?;
                        continue;
                    }
                    e => {
                        eprintln!("error reading lock: {}", e);
                        return Err(anyhow!("{}", e));
                    }
                },
            };
            info!("stopping {} pid: {}", daemon_name, pid);
            print!("stopping {}...", &daemon_name);
            match iroh_localops::process::stop(pid) {
                Ok(_) => {
                    println!("{}", "stopped".red());
                }
                Err(e) => {
                    // if killing the process errored out, try to remove the lockfile
                    if try_cleanup_dead_lock(daemon_name)? {
                        println!("removed dead lockfile for {} daemon", daemon_name);
                        println!("{}", "stopped".red());
                    } else {
                        println!("{}: {}", "error".yellow(), e);
                    }
                }
            }
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
                w.queue(style::PrintStyledContent("Down".red()))?
                    .queue(style::Print(format!("\t{}", code)))?;
            }
        },
    };
    w.queue(style::Print("\n"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_table_queue() {
        let expect = format!("{}gateway\t\t\t1/1\t{}\np2p\t\t\t1/1\t{}\nstore\t\t\t1/1\t{}\tThe service is currently unavailable\n", "Process\t\t\tNumber\tStatus\n".bold(), "Unknown".dark_yellow(), "Serving".green(), "Down".red());
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
                    "Down".red()
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
