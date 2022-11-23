use crate::{gateway, network, store};
use anyhow::Result;
use async_stream::stream;
use futures::Stream;
use tonic::transport::channel::Channel;
use tonic_health::proto::{
    health_check_response::ServingStatus, health_client::HealthClient, HealthCheckRequest,
    HealthCheckResponse,
};

// TODO: make configurable
const WAIT: std::time::Duration = std::time::Duration::from_millis(1000);

#[tracing::instrument(skip(health_client))]
pub async fn check(
    health_client: HealthClient<Channel>,
    service: &'static str,
    display_name: &'static str,
) -> StatusRow {
    let req = iroh_metrics::req::trace_tonic_req(HealthCheckRequest {
        service: service.to_string(),
    });
    let res = health_client.clone().check(req).await;
    let status = match res {
        Ok(res) => res.into_inner().into(),
        Err(s) => ServiceStatus::Down(s),
    };
    StatusRow::new(display_name, 1, status)
}

#[tracing::instrument(skip(health_client))]
pub async fn watch(
    health_client: HealthClient<Channel>,
    service: &'static str,
    display_name: &'static str,
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
                            Ok(Some(message)) => yield StatusRow::new(display_name, 1, message.into()),
                            Ok(None) => {
                                yield StatusRow::new(display_name, 1, ServiceStatus::Down(tonic::Status::new(tonic::Code::Unavailable, format!("No more health messages from service `{}`", service))));
                                break;
                            }
                            Err(status) => {
                                yield StatusRow::new(display_name, 1, ServiceStatus::Down(status));
                                break;
                            }
                        }
                    }
                },
                Err(status) => yield StatusRow::new(display_name, 1, ServiceStatus::Down(status)),
            }
            /// wait before attempting to start a watch stream again
            tokio::time::sleep(WAIT).await;
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

// Should only be used for testing purposes
// Implementation does not compare `ServiceStatus::Down(tonic::Status)`
// with thorough rigor
impl std::cmp::PartialEq for ServiceStatus {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (ServiceStatus::Unknown, ServiceStatus::Unknown) => true,
            (ServiceStatus::Serving, ServiceStatus::Serving) => true,
            (ServiceStatus::NotServing, ServiceStatus::NotServing) => true,
            (ServiceStatus::ServiceUnknown, ServiceStatus::ServiceUnknown) => true,
            (ServiceStatus::Down(s), ServiceStatus::Down(o)) => s.code() == o.code(),
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StatusRow {
    pub(crate) name: &'static str,
    pub(crate) number: usize,
    pub(crate) status: ServiceStatus,
}

impl StatusRow {
    pub fn new(name: &'static str, number: usize, status: ServiceStatus) -> Self {
        Self {
            name,
            number,
            status,
        }
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    pub fn number(&self) -> usize {
        self.number
    }

    pub fn status(&self) -> ServiceStatus {
        self.status.clone()
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

#[derive(Debug, Clone, PartialEq)]
pub struct StatusTable {
    pub gateway: StatusRow,
    pub p2p: StatusRow,
    pub store: StatusRow,
}

impl StatusTable {
    pub fn new(
        gateway: Option<StatusRow>,
        p2p: Option<StatusRow>,
        store: Option<StatusRow>,
    ) -> Self {
        Self {
            gateway: gateway.unwrap_or_default(),
            p2p: p2p.unwrap_or_default(),
            store: store.unwrap_or_default(),
        }
    }

    pub fn iter(&self) -> StatusTableIterator<'_> {
        StatusTableIterator {
            table: self,
            iter: 0,
        }
    }

    pub fn update(&mut self, s: StatusRow) -> Result<()> {
        if self.gateway.name() == s.name() {
            self.gateway = s;
            return Ok(());
        }
        if self.p2p.name() == s.name() {
            self.p2p = s;
            return Ok(());
        }
        if self.store.name() == s.name() {
            self.store = s;
            return Ok(());
        }
        Err(anyhow::anyhow!("unknown service {}", s.name))
    }
}

pub struct StatusTableIterator<'a> {
    table: &'a StatusTable,
    iter: usize,
}

impl Iterator for StatusTableIterator<'_> {
    type Item = StatusRow;

    fn next(&mut self) -> Option<Self::Item> {
        let current = match self.iter {
            0 => Some(self.table.store.to_owned()),
            1 => Some(self.table.p2p.to_owned()),
            2 => Some(self.table.gateway.to_owned()),
            _ => None,
        };

        self.iter += 1;
        current
    }
}

impl Default for StatusTable {
    fn default() -> Self {
        Self {
            gateway: StatusRow::new(gateway::NAME, 1, ServiceStatus::Unknown),
            p2p: StatusRow::new(network::NAME, 1, ServiceStatus::Unknown),
            store: StatusRow::new(store::NAME, 1, ServiceStatus::Unknown),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_row_default() {
        let expect = StatusRow {
            name: "",
            number: 1,
            status: ServiceStatus::Unknown,
        };
        assert_eq!(expect, Default::default());
    }

    #[test]
    fn status_row_new() {
        let expect = StatusRow {
            name: "test",
            number: 15,
            status: ServiceStatus::NotServing,
        };
        assert_eq!(
            expect,
            StatusRow::new("test", 15, ServiceStatus::NotServing)
        );
    }

    #[test]
    fn status_table_default() {
        let expect = StatusTable {
            gateway: StatusRow {
                name: crate::gateway::NAME,
                number: 1,
                status: ServiceStatus::Unknown,
            },
            p2p: StatusRow {
                name: crate::network::NAME,
                number: 1,
                status: ServiceStatus::Unknown,
            },
            store: StatusRow {
                name: crate::store::NAME,
                number: 1,
                status: ServiceStatus::Unknown,
            },
        };

        assert_eq!(expect, StatusTable::default());
    }

    #[test]
    fn status_table_new() {
        let expect = StatusTable {
            gateway: StatusRow {
                name: "test",
                number: 1,
                status: ServiceStatus::Unknown,
            },
            p2p: StatusRow {
                name: "test",
                number: 1,
                status: ServiceStatus::Unknown,
            },
            store: StatusRow {
                name: "test",
                number: 1,
                status: ServiceStatus::Unknown,
            },
        };
        assert_eq!(
            expect,
            StatusTable::new(
                Some(StatusRow::new("test", 1, ServiceStatus::Unknown)),
                Some(StatusRow::new("test", 1, ServiceStatus::Unknown)),
                Some(StatusRow::new("test", 1, ServiceStatus::Unknown))
            )
        );
    }

    #[test]
    fn status_table_update() {
        let mut gateway = Some(StatusRow::new(gateway::NAME, 1, ServiceStatus::Unknown));
        let mut p2p = Some(StatusRow::new(network::NAME, 1, ServiceStatus::Unknown));
        let mut store = Some(StatusRow::new(store::NAME, 1, ServiceStatus::Unknown));
        let mut got = StatusTable::new(gateway.clone(), p2p.clone(), store.clone());

        store.as_mut().unwrap().status = ServiceStatus::Serving;
        let expect = StatusTable::new(gateway.clone(), p2p.clone(), store.clone());
        got.update(store.clone().unwrap()).unwrap();
        assert_eq!(expect, got);

        gateway.as_mut().unwrap().status = ServiceStatus::ServiceUnknown;
        let expect = StatusTable::new(gateway.clone(), p2p.clone(), store.clone());
        got.update(gateway.clone().unwrap()).unwrap();
        assert_eq!(expect, got);

        p2p.as_mut().unwrap().status =
            ServiceStatus::Down(tonic::Status::new(tonic::Code::Unavailable, ""));
        let expect = StatusTable::new(gateway, p2p.clone(), store);
        got.update(p2p.unwrap()).unwrap();
        assert_eq!(expect, got);
    }

    #[test]
    fn status_table_iter() {
        let table = StatusTable::default();
        let rows: Vec<StatusRow> = table.iter().collect();
        assert_eq!(
            vec![
                StatusRow {
                    name: crate::store::NAME,
                    number: 1,
                    status: ServiceStatus::Unknown,
                },
                StatusRow {
                    name: crate::network::NAME,
                    number: 1,
                    status: ServiceStatus::Unknown,
                },
                StatusRow {
                    name: crate::gateway::NAME,
                    number: 1,
                    status: ServiceStatus::Unknown,
                },
            ],
            rows
        );
    }
}
