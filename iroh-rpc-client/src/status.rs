use std::io::Write;

use anyhow::Result;
use async_stream::stream;
use crossterm::{
    style::{self, Stylize},
    QueueableCommand,
};
use futures::Stream;
use tonic::transport::channel::Channel;
use tonic_health::proto::{
    health_check_response::ServingStatus, health_client::HealthClient, HealthCheckRequest,
    HealthCheckResponse,
};

#[tracing::instrument(skip(health_client))]
pub async fn check(health_client: HealthClient<Channel>, service: &'static str) -> StatusRow {
    let req = iroh_metrics::req::trace_tonic_req(HealthCheckRequest {
        service: service.to_string(),
    });
    let res = health_client.clone().check(req).await;
    let status = match res {
        Ok(res) => res.into_inner().into(),
        Err(s) => ServiceStatus::Down(s),
    };
    StatusRow::new(service, 1, status)
}

#[tracing::instrument(skip(health_client))]
pub async fn watch(
    health_client: HealthClient<Channel>,
    service: &'static str,
) -> impl Stream<Item = StatusRow> {
    stream! {
        loop {
            let req = iroh_metrics::req::trace_tonic_req(HealthCheckRequest { service: service.to_string() });
            let res = health_client.clone().watch(req).await;
            match res {
                Ok(stream) => {
                    let mut stream = stream.into_inner();
                    // loop over the stream, breaking if we get an error or stop receiving messages
                    loop {
                        match stream.message().await {
                            Ok(Some(message)) => yield StatusRow::new(service, 1, message.into()),
                            Ok(None) => {
                                yield StatusRow::new(service, 1, ServiceStatus::Down(tonic::Status::new(tonic::Code::Unavailable, format!("No more health messages from service `{}`", service))));
                                break;
                            }
                            Err(status) => {
                                yield StatusRow::new(service, 1, ServiceStatus::Down(status));
                                break;
                            }
                        }
                    }
                },
                Err(status) => yield StatusRow::new(service, 1, ServiceStatus::Down(status)),
            }
            /// wait before attempting to start a watch stream again
            tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
        };
    }
}

impl std::convert::From<HealthCheckResponse> for ServiceStatus {
    fn from(h: HealthCheckResponse) -> Self {
        match h.status() {
            ServingStatus::Unknown => ServiceStatus::Unknown,
            ServingStatus::Serving => ServiceStatus::Serving,
            ServingStatus::NotServing => ServiceStatus::NotServing,
            ServingStatus::ServiceUnknown => ServiceStatus::ServiceUnknown,
        }
    }
}

#[derive(Debug)]
pub enum ServiceStatus {
    ///  Indicates rpc server is in an unknown state
    Unknown,
    /// Indicates service is serving data
    Serving,
    /// Indicates service is not serving data, but the rpc server is not down
    NotServing,
    /// Indicates that the requested service is unknown
    ServiceUnknown,
    /// Indicates that the service is down. This ServiceStatus is assigned when
    /// a `check` or `watch` call has returned an error with `tonic::Status`
    Down(tonic::Status),
}

impl std::clone::Clone for ServiceStatus {
    fn clone(&self) -> Self {
        match self {
            ServiceStatus::Down(status) => {
                ServiceStatus::Down(tonic::Status::new(status.code(), status.message()))
            }
            ServiceStatus::Unknown => ServiceStatus::Unknown,
            ServiceStatus::Serving => ServiceStatus::Serving,
            ServiceStatus::NotServing => ServiceStatus::NotServing,
            ServiceStatus::ServiceUnknown => ServiceStatus::ServiceUnknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StatusRow {
    name: &'static str,
    number: usize,
    status: ServiceStatus,
}

impl StatusRow {
    fn new(name: &'static str, number: usize, status: ServiceStatus) -> Self {
        Self {
            name,
            number,
            status,
        }
    }

    // queue_status_table_row queues this row of the StatusRow to be written
    // You must call `writer.flush()` to actually write the content to the writer
    fn queue_status_table_row<W>(&self, w: &mut W) -> Result<()>
    where
        W: Write,
    {
        w.queue(style::Print(format!("{}\t\t\t", self.name)))?
            .queue(style::Print(format!("{}/1\t", self.number)))?;
        match &self.status {
            ServiceStatus::Unknown => {
                w.queue(style::PrintStyledContent("Unknown".dark_yellow()))?;
            }
            ServiceStatus::NotServing => {
                w.queue(style::PrintStyledContent("NotServing".dark_yellow()))?;
            }
            ServiceStatus::Serving => {
                w.queue(style::PrintStyledContent("Serving".green()))?;
            }
            ServiceStatus::ServiceUnknown => {
                w.queue(style::PrintStyledContent("Service Unknown".dark_yellow()))?;
            }
            ServiceStatus::Down(status) => match status.code() {
                tonic::Code::Unknown => {
                    w.queue(style::PrintStyledContent("Down\t".dark_yellow()))?
                        .queue(style::Print("The service has been interupted"))?;
                }
                code => {
                    w.queue(style::PrintStyledContent("Down\t".red()))?
                        .queue(style::Print(format!("{}\t", code)))?;
                }
            },
        };
        w.queue(style::Print("\n"))?;
        Ok(())
    }
}

impl Default for StatusRow {
    fn default() -> Self {
        Self {
            name: "",
            number: 1,
            status: ServiceStatus::Unknown,
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct StatusTable {
    gateway: StatusRow,
    p2p: StatusRow,
    store: StatusRow,
}

impl StatusTable {
    pub fn new(gateway: StatusRow, p2p: StatusRow, store: StatusRow) -> Self {
        Self {
            gateway,
            p2p,
            store,
        }
    }

    pub fn update(&mut self, s: StatusRow) -> Result<()> {
        match s.name {
            "gateway" => {
                self.gateway = s;
                Ok(())
            }
            "p2p" => {
                self.p2p = s;
                Ok(())
            }
            "store" => {
                self.store = s;
                Ok(())
            }
            _ => Err(anyhow::anyhow!("unknown service {}", s.name)),
        }
    }

    /// queues the table for printing
    /// you must call `writer.flush()` to execute the queue
    pub fn queue_table<W>(&self, mut w: W) -> Result<()>
    where
        W: Write,
    {
        w.queue(style::PrintStyledContent(
            "Process\t\t\tNumber\tStatus\n".bold(),
        ))?;
        self.gateway.queue_status_table_row(&mut w)?;
        self.p2p.queue_status_table_row(&mut w)?;
        self.gateway.queue_status_table_row(&mut w)?;
        Ok(())
    }
}
