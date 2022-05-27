use std::collections::HashMap;
use std::io::{stdout, Write};

use crossterm::terminal::{Clear, ClearType};
use crossterm::{
    cursor,
    style::{self, Attribute, Color, Stylize},
    QueueableCommand,
};
use futures::StreamExt;

use anyhow::Result;
use iroh_rpc_client::{Client, RpcClientConfig, ServiceStatus};

pub(crate) async fn status(watch: bool) -> Result<()> {
    let client = Client::new(&RpcClientConfig::default()).await.unwrap();

    let mut stdout = stdout();
    if watch {
        let status_stream = client.watch().await;
        futures::pin_mut!(status_stream);
        stdout.queue(Clear(ClearType::All))?;
        while let Some(s) = status_stream.next().await {
            stdout
                .queue(cursor::RestorePosition)?
                .queue(Clear(ClearType::FromCursorUp))?
                .queue(cursor::MoveTo(0, 1))?;
            queue_status_table(&stdout, s)?;
            stdout
                .queue(cursor::SavePosition)?
                .queue(style::Print("\n"))?
                .flush()?;
        }
        Ok(())
    } else {
        let s = client.check().await;
        queue_status_table(&stdout, s)?;
        stdout.flush()?;
        Ok(())
    }
}

fn queue_status_table(
    mut stdout: &std::io::Stdout,
    statuses: HashMap<String, ServiceStatus>,
) -> Result<()> {
    let mut v: Vec<StatusTable> = Vec::new();
    v.push(StatusTable {
        name: "gateway".into(),
        number: 1,
        status: statuses.get("gateway").unwrap().clone(),
    });

    v.push(StatusTable {
        name: "p2p".into(),
        number: 1,
        status: statuses.get("p2p").unwrap().clone(),
    });

    v.push(StatusTable {
        name: "store".into(),
        number: 1,
        status: statuses.get("store").unwrap().clone(),
    });

    stdout.queue(style::PrintStyledContent(
        "Process\t\t\tNumber\tStatus\n".attribute(Attribute::Bold),
    ))?;

    for s in v {
        stdout
            .queue(style::Print(format!("{}\t\t\t", s.name)))?
            .queue(style::Print(format!("{}/1\t", s.number)))?;
        match s.status {
            ServiceStatus::Unknown => {
                stdout.queue(style::PrintStyledContent("Unknown".with(Color::DarkYellow)))?;
            }
            ServiceStatus::NotServing => {
                stdout.queue(style::PrintStyledContent(
                    "NotServing".with(Color::DarkYellow),
                ))?;
            }
            ServiceStatus::Serving => {
                stdout.queue(style::PrintStyledContent("Serving".with(Color::Green)))?;
            }
            ServiceStatus::ServiceUnknown => {
                stdout.queue(style::PrintStyledContent(
                    "Service Unknown".with(Color::DarkYellow),
                ))?;
            }
            ServiceStatus::Down(status) => match status.code() {
                tonic::Code::Unknown => {
                    stdout
                        .queue(style::PrintStyledContent("Down\t".with(Color::DarkYellow)))?
                        .queue(style::Print("The service has been interupted"))?;
                }
                code => {
                    stdout
                        .queue(style::PrintStyledContent("Down\t".with(Color::Red)))?
                        .queue(style::Print(format!("{}\t", code)))?;
                }
            },
        };
        stdout.queue(style::Print("\n"))?;
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct StatusTable {
    name: String,
    number: usize,
    status: ServiceStatus,
}
