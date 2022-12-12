use crate::{gateway, network, store};
use anyhow::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceStatus {
    ///  Indicates rpc server is in an unknown state
    Unknown,
    /// Indicates service is serving data
    Serving,
    /// Indicates service is not serving data, but the rpc server is not down
    NotServing,
    /// Indicates that the requested service is unknown
    ServiceUnknown,
    /// Indicates that the service is down.
    Down,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug)]
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

        p2p.as_mut().unwrap().status = ServiceStatus::Down;
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
