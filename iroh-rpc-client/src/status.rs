use crate::{gateway, network, store};
use anyhow::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusType {
    /// Indicates service status is unknown
    Unknown,
    /// Indicates service is serving data
    Serving,
    /// Indicates that the service is down.
    Down,
    /// Indicates that the service not serving data, but the service is not down.
    // TODO(ramfox): NotServing is currently unused
    NotServing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The status of an individual rpc service
pub struct ServiceStatus {
    /// name of the service: "gateway", "p2p", or "store"
    pub(crate) name: &'static str,
    pub(crate) status: StatusType,
    pub(crate) version: String,
}

impl ServiceStatus {
    pub fn new<I: Into<String>>(name: &'static str, status: StatusType, version: I) -> Self {
        Self {
            name,
            status,
            version: version.into(),
        }
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    pub fn status(&self) -> StatusType {
        self.status.clone()
    }

    pub fn version(&self) -> &str {
        &self.version
    }
}

impl Default for ServiceStatus {
    fn default() -> Self {
        Self {
            name: "",
            status: StatusType::Unknown,
            version: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientStatus {
    pub gateway: ServiceStatus,
    pub p2p: ServiceStatus,
    pub store: ServiceStatus,
}

impl ClientStatus {
    pub fn new(
        gateway: Option<ServiceStatus>,
        p2p: Option<ServiceStatus>,
        store: Option<ServiceStatus>,
    ) -> Self {
        Self {
            gateway: gateway.unwrap_or_default(),
            p2p: p2p.unwrap_or_default(),
            store: store.unwrap_or_default(),
        }
    }

    pub fn iter(&self) -> ClientStatusIterator<'_> {
        ClientStatusIterator {
            table: self,
            iter: 0,
        }
    }

    pub fn update(&mut self, s: ServiceStatus) -> Result<()> {
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

#[derive(Debug)]
pub struct ClientStatusIterator<'a> {
    table: &'a ClientStatus,
    iter: usize,
}

impl Iterator for ClientStatusIterator<'_> {
    type Item = ServiceStatus;

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

impl Default for ClientStatus {
    fn default() -> Self {
        Self {
            gateway: ServiceStatus::new(gateway::NAME, StatusType::Unknown, ""),
            p2p: ServiceStatus::new(network::NAME, StatusType::Unknown, ""),
            store: ServiceStatus::new(store::NAME, StatusType::Unknown, ""),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_status_default() {
        let expect = ServiceStatus {
            name: "",
            status: StatusType::Unknown,
            version: String::new(),
        };
        assert_eq!(expect, Default::default());
    }

    #[test]
    fn service_status_new() {
        let expect = ServiceStatus {
            name: "test",
            status: StatusType::Serving,
            version: "v0.1.0".to_string(),
        };
        assert_eq!(
            expect,
            ServiceStatus::new("test", StatusType::Serving, "v0.1.0")
        );
    }

    #[test]
    fn client_status_default() {
        let expect = ClientStatus {
            gateway: ServiceStatus {
                name: crate::gateway::NAME,
                status: StatusType::Unknown,
                version: "".to_string(),
            },
            p2p: ServiceStatus {
                name: crate::network::NAME,
                status: StatusType::Unknown,
                version: "".to_string(),
            },
            store: ServiceStatus {
                name: crate::store::NAME,
                status: StatusType::Unknown,
                version: "".to_string(),
            },
        };

        assert_eq!(expect, ClientStatus::default());
    }

    #[test]
    fn status_table_new() {
        let expect = ClientStatus {
            gateway: ServiceStatus {
                name: "test",
                status: StatusType::Unknown,
                version: "test".to_string(),
            },
            p2p: ServiceStatus {
                name: "test",
                status: StatusType::Unknown,
                version: "test".to_string(),
            },
            store: ServiceStatus {
                name: "test",
                status: StatusType::Unknown,
                version: "test".to_string(),
            },
        };
        assert_eq!(
            expect,
            ClientStatus::new(
                Some(ServiceStatus::new("test", StatusType::Unknown, "test")),
                Some(ServiceStatus::new("test", StatusType::Unknown, "test")),
                Some(ServiceStatus::new("test", StatusType::Unknown, "test"))
            )
        );
    }

    #[test]
    fn status_table_update() {
        let gateway = Some(ServiceStatus::new(
            gateway::NAME,
            StatusType::Unknown,
            "v0.1.0",
        ));
        let mut p2p = Some(ServiceStatus::new(
            network::NAME,
            StatusType::Unknown,
            "v0.1.0",
        ));
        let mut store = Some(ServiceStatus::new(
            store::NAME,
            StatusType::Unknown,
            "v0.1.0",
        ));
        let mut got = ClientStatus::new(gateway.clone(), p2p.clone(), store.clone());

        store.as_mut().unwrap().status = StatusType::Serving;
        let expect = ClientStatus::new(gateway.clone(), p2p.clone(), store.clone());
        got.update(store.clone().unwrap()).unwrap();
        assert_eq!(expect, got);

        p2p.as_mut().unwrap().status = StatusType::Down;
        let expect = ClientStatus::new(gateway, p2p.clone(), store);
        got.update(p2p.unwrap()).unwrap();
        assert_eq!(expect, got);
    }

    #[test]
    fn status_table_iter() {
        let table = ClientStatus::default();
        let rows: Vec<ServiceStatus> = table.iter().collect();
        assert_eq!(
            vec![
                ServiceStatus {
                    name: crate::store::NAME,
                    status: StatusType::Unknown,
                    version: "".to_string(),
                },
                ServiceStatus {
                    name: crate::network::NAME,
                    status: StatusType::Unknown,
                    version: "".to_string(),
                },
                ServiceStatus {
                    name: crate::gateway::NAME,
                    status: StatusType::Unknown,
                    version: "".to_string(),
                },
            ],
            rows
        );
    }
}
