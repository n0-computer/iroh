use std::time::Duration;

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

pub const HEALTH_POLL_WAIT: Duration = std::time::Duration::from_secs(1);

#[derive(Debug, Clone, PartialEq, Eq)]
/// The status of an individual rpc service
pub struct ServiceStatus {
    typ: ServiceType,
    status: StatusType,
    version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceType {
    Gateway,
    P2p,
    Store,
}

impl ServiceType {
    pub fn name(&self) -> &'static str {
        match self {
            ServiceType::Gateway => "gateway",
            ServiceType::P2p => "p2p",
            ServiceType::Store => "store",
        }
    }
}

impl ServiceStatus {
    pub fn new<I: Into<String>>(typ: ServiceType, status: StatusType, version: I) -> Self {
        Self {
            typ,
            status,
            version: version.into(),
        }
    }

    pub fn name(&self) -> &'static str {
        self.typ.name()
    }

    pub fn status(&self) -> StatusType {
        self.status.clone()
    }

    pub fn version(&self) -> &str {
        if self.version.is_empty() {
            "unknown"
        } else {
            &self.version
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
            gateway: gateway.unwrap_or_else(|| {
                ServiceStatus::new(ServiceType::Gateway, StatusType::Unknown, "")
            }),
            p2p: p2p
                .unwrap_or_else(|| ServiceStatus::new(ServiceType::P2p, StatusType::Unknown, "")),
            store: store
                .unwrap_or_else(|| ServiceStatus::new(ServiceType::Store, StatusType::Unknown, "")),
        }
    }

    pub fn iter(&self) -> ClientStatusIterator<'_> {
        ClientStatusIterator {
            table: self,
            iter: 0,
        }
    }

    pub fn update(&mut self, s: ServiceStatus) {
        match s.typ {
            ServiceType::Gateway => self.gateway = s,
            ServiceType::P2p => self.p2p = s,
            ServiceType::Store => self.store = s,
        }
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
        Self::new(None, None, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_status_new() {
        let expect = ServiceStatus {
            typ: ServiceType::Gateway,
            status: StatusType::Serving,
            version: "0.1.0".to_string(),
        };
        assert_eq!(
            expect,
            ServiceStatus::new(ServiceType::Gateway, StatusType::Serving, "0.1.0")
        );
    }

    #[test]
    fn client_status_default() {
        let expect = ClientStatus {
            gateway: ServiceStatus {
                typ: ServiceType::Gateway,
                status: StatusType::Unknown,
                version: "".to_string(),
            },
            p2p: ServiceStatus {
                typ: ServiceType::P2p,
                status: StatusType::Unknown,
                version: "".to_string(),
            },
            store: ServiceStatus {
                typ: ServiceType::Store,
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
                typ: ServiceType::Gateway,
                status: StatusType::Unknown,
                version: "test".to_string(),
            },
            p2p: ServiceStatus {
                typ: ServiceType::P2p,
                status: StatusType::Unknown,
                version: "test".to_string(),
            },
            store: ServiceStatus {
                typ: ServiceType::Store,
                status: StatusType::Unknown,
                version: "test".to_string(),
            },
        };
        assert_eq!(
            expect,
            ClientStatus::new(
                Some(ServiceStatus::new(
                    ServiceType::Gateway,
                    StatusType::Unknown,
                    "test"
                )),
                Some(ServiceStatus::new(
                    ServiceType::P2p,
                    StatusType::Unknown,
                    "test"
                )),
                Some(ServiceStatus::new(
                    ServiceType::Store,
                    StatusType::Unknown,
                    "test"
                ))
            )
        );
    }

    #[test]
    fn status_table_update() {
        let gateway = Some(ServiceStatus::new(
            ServiceType::Gateway,
            StatusType::Unknown,
            "0.1.0",
        ));
        let mut p2p = Some(ServiceStatus::new(
            ServiceType::P2p,
            StatusType::Unknown,
            "0.1.0",
        ));
        let mut store = Some(ServiceStatus::new(
            ServiceType::Store,
            StatusType::Unknown,
            "0.1.0",
        ));
        let mut got = ClientStatus::new(gateway.clone(), p2p.clone(), store.clone());

        store.as_mut().unwrap().status = StatusType::Serving;
        let expect = ClientStatus::new(gateway.clone(), p2p.clone(), store.clone());
        got.update(store.clone().unwrap());
        assert_eq!(expect, got);

        p2p.as_mut().unwrap().status = StatusType::Down;
        let expect = ClientStatus::new(gateway, p2p.clone(), store);
        got.update(p2p.unwrap());
        assert_eq!(expect, got);
    }

    #[test]
    fn status_table_iter() {
        let table = ClientStatus::default();
        let rows: Vec<ServiceStatus> = table.iter().collect();
        assert_eq!(
            vec![
                ServiceStatus {
                    typ: ServiceType::Store,
                    status: StatusType::Unknown,
                    version: "".to_string(),
                },
                ServiceStatus {
                    typ: ServiceType::P2p,
                    status: StatusType::Unknown,
                    version: "".to_string(),
                },
                ServiceStatus {
                    typ: ServiceType::Gateway,
                    status: StatusType::Unknown,
                    version: "".to_string(),
                },
            ],
            rows
        );
    }
}
