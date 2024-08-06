use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use clap::Subcommand;
use colored::Colorize;
use comfy_table::Table;
use comfy_table::{presets::NOTHING, Cell};
use futures_lite::{Stream, StreamExt};
use human_time::ToHumanTimeString;
use iroh::client::Iroh;
use iroh::net::endpoint::{ConnectionInfo, DirectAddrInfo};
use iroh::net::relay::RelayUrl;
use iroh::net::{NodeAddr, NodeId};

#[derive(Subcommand, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum NodeCommands {
    /// Get information about the different connections we have made
    Connections,
    /// Get connection information about a particular node
    ConnectionInfo { node_id: NodeId },
    /// Get status of the running node.
    Status,
    /// Get statistics and metrics from the running node.
    Stats,
    /// Shutdown the running node.
    Shutdown {
        /// Shutdown mode.
        ///
        /// Hard shutdown will immediately terminate the process, soft shutdown will wait
        /// for all connections to close.
        #[clap(long, default_value_t = false)]
        force: bool,
    },
    /// Get the node addr of this node.
    NodeAddr,
    /// Add this node addr to the known nodes.
    AddNodeAddr {
        node_id: NodeId,
        relay: Option<RelayUrl>,
        addresses: Vec<SocketAddr>,
    },
    /// Get the relay server we are connected to.
    HomeRelay,
}

impl NodeCommands {
    pub async fn run(self, iroh: &Iroh) -> Result<()> {
        match self {
            Self::Connections => {
                let connections = iroh.connections().await?;
                let timestamp = time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc2822)
                    .unwrap_or_else(|_| String::from("failed to get current time"));

                println!(
                    " {}: {}\n\n{}",
                    "current time".bold(),
                    timestamp,
                    fmt_connections(connections).await
                );
            }
            Self::ConnectionInfo { node_id } => {
                let conn_info = iroh.connection_info(node_id).await?;
                match conn_info {
                    Some(info) => println!("{}", fmt_connection(info)),
                    None => println!("Not Found"),
                }
            }
            Self::Shutdown { force } => {
                iroh.shutdown(force).await?;
            }
            Self::Stats => {
                let stats = iroh.stats().await?;
                for (name, details) in stats.iter() {
                    println!(
                        "{:23} : {:>6}    ({})",
                        name, details.value, details.description
                    );
                }
            }
            Self::Status => {
                let response = iroh.status().await?;
                println!("Listening addresses: {:#?}", response.listen_addrs);
                println!("Node ID: {}", response.addr.node_id);
                println!("Version: {}", response.version);
                if let Some(addr) = response.rpc_addr {
                    println!("RPC Addr: {}", addr);
                }
            }
            Self::NodeAddr => {
                let addr = iroh.node_addr().await?;
                println!("Node ID: {}", addr.node_id);
                let relay = addr
                    .info
                    .relay_url
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "Not Available".to_string());
                println!("Home Relay: {}", relay);
                println!("Direct Addresses ({}):", addr.info.direct_addresses.len());
                for da in &addr.info.direct_addresses {
                    println!(" {}", da);
                }
            }
            Self::AddNodeAddr {
                node_id,
                relay,
                addresses,
            } => {
                let mut addr = NodeAddr::new(node_id).with_direct_addresses(addresses);
                if let Some(relay) = relay {
                    addr = addr.with_relay_url(relay);
                }
                iroh.add_node_addr(addr).await?;
            }
            Self::HomeRelay => {
                let relay = iroh.home_relay().await?;
                let relay = relay
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "Not Available".to_string());
                println!("Home Relay: {}", relay);
            }
        }
        Ok(())
    }
}

async fn fmt_connections(
    mut infos: impl Stream<Item = Result<ConnectionInfo, anyhow::Error>> + Unpin,
) -> String {
    let mut table = Table::new();
    table.load_preset(NOTHING).set_header(
        ["node id", "relay", "conn type", "latency", "last used"]
            .into_iter()
            .map(bold_cell),
    );
    while let Some(Ok(conn_info)) = infos.next().await {
        let node_id: Cell = conn_info.node_id.to_string().into();
        let relay_url = conn_info
            .relay_url
            .map_or(String::new(), |url_info| url_info.relay_url.to_string())
            .into();
        let conn_type = conn_info.conn_type.to_string().into();
        let latency = match conn_info.latency {
            Some(latency) => latency.to_human_time_string(),
            None => String::from("unknown"),
        }
        .into();
        let last_used = conn_info
            .last_used
            .map(fmt_how_long_ago)
            .map(Cell::new)
            .unwrap_or_else(never);
        table.add_row([node_id, relay_url, conn_type, latency, last_used]);
    }
    table.to_string()
}

fn fmt_connection(info: ConnectionInfo) -> String {
    let ConnectionInfo {
        id: _,
        node_id,
        relay_url,
        addrs,
        conn_type,
        latency,
        last_used,
    } = info;
    let timestamp = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc2822)
        .unwrap_or_else(|_| String::from("failed to get current time"));
    let mut table = Table::new();
    table.load_preset(NOTHING);
    table.add_row([bold_cell("current time"), timestamp.into()]);
    table.add_row([bold_cell("node id"), node_id.to_string().into()]);
    let relay_url = relay_url
        .map(|r| r.relay_url.to_string())
        .unwrap_or_else(|| String::from("unknown"));
    table.add_row([bold_cell("relay url"), relay_url.into()]);
    table.add_row([bold_cell("connection type"), conn_type.to_string().into()]);
    table.add_row([bold_cell("latency"), fmt_latency(latency).into()]);
    table.add_row([
        bold_cell("last used"),
        last_used
            .map(fmt_how_long_ago)
            .map(Cell::new)
            .unwrap_or_else(never),
    ]);
    table.add_row([bold_cell("known addresses"), addrs.len().into()]);

    let general_info = table.to_string();

    let addrs_info = fmt_addrs(addrs);
    format!("{general_info}\n\n{addrs_info}",)
}

fn direct_addr_row(info: DirectAddrInfo) -> comfy_table::Row {
    let DirectAddrInfo {
        addr,
        latency,
        last_control,
        last_payload,
        last_alive,
    } = info;

    let last_control = match last_control {
        None => never(),
        Some((how_long_ago, kind)) => {
            format!("{kind} ( {} )", fmt_how_long_ago(how_long_ago)).into()
        }
    };
    let last_payload = last_payload
        .map(fmt_how_long_ago)
        .map(Cell::new)
        .unwrap_or_else(never);

    let last_alive = last_alive
        .map(fmt_how_long_ago)
        .map(Cell::new)
        .unwrap_or_else(never);

    [
        addr.into(),
        fmt_latency(latency).into(),
        last_control,
        last_payload,
        last_alive,
    ]
    .into()
}

fn fmt_addrs(addrs: Vec<DirectAddrInfo>) -> comfy_table::Table {
    let mut table = Table::new();
    table.load_preset(NOTHING).set_header(
        vec!["addr", "latency", "last control", "last data", "last alive"]
            .into_iter()
            .map(bold_cell),
    );
    table.add_rows(addrs.into_iter().map(direct_addr_row));
    table
}

fn never() -> Cell {
    Cell::new("never").add_attribute(comfy_table::Attribute::Dim)
}

fn fmt_how_long_ago(duration: Duration) -> String {
    duration
        .to_human_time_string()
        .split_once(',')
        .map(|(first, _rest)| first)
        .unwrap_or("-")
        .to_string()
}

fn fmt_latency(latency: Option<Duration>) -> String {
    match latency {
        Some(latency) => latency.to_human_time_string(),
        None => String::from("unknown"),
    }
}

fn bold_cell(s: &str) -> Cell {
    Cell::new(s).add_attribute(comfy_table::Attribute::Bold)
}
