use std::io::{stdout, Write};

use anyhow::Result;
use crossterm::terminal::{Clear, ClearType};
use crossterm::{cursor, style, style::Stylize, QueueableCommand};
use futures::StreamExt;
use iroh::{Api, ServiceStatus, StatusRow, StatusTable};

pub async fn status(api: &impl Api, watch: bool) -> Result<()> {
    let mut stdout = stdout();
    if watch {
        // XXX this requires an implementation of watch on the API
        // let status_stream = api.watch().await;
        // tokio::pin!(status_stream);
        // stdout.queue(Clear(ClearType::All))?;
        // while let Some(table) = status_stream.next().await {
        //     stdout
        //         .queue(cursor::RestorePosition)?
        //         .queue(Clear(ClearType::FromCursorUp))?
        //         .queue(cursor::MoveTo(0, 1))?;
        //     queue_table(&table, &stdout)?;
        //     stdout
        //         .queue(cursor::SavePosition)?
        //         .queue(style::Print("\n"))?
        //         .flush()?;
        // }
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
