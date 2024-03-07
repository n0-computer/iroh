use std::time::Duration;

use anyhow::Result;
use clap::Subcommand;
use colored::Colorize;
use comfy_table::Table;
use comfy_table::{presets::NOTHING, Cell};
use futures::{Stream, StreamExt};
use human_time::ToHumanTimeString;
use iroh::client::Iroh;
use iroh::rpc_protocol::ProviderService;
use iroh_net::{key::PublicKey, magic_endpoint::ConnectionInfo, magicsock::DirectAddrInfo};
use quic_rpc::ServiceConnection;

#[derive(Subcommand, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum NodeCommands {
    /// Get information about the different connections we have made
    Connections,
    /// Get connection information about a particular node
    Connection { node_id: PublicKey },
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
}

impl NodeCommands {
    pub async fn run<C>(self, iroh: &Iroh<C>) -> Result<()>
    where
        C: ServiceConnection<ProviderService>,
    {
        match self {
            Self::Connections => {
                let connections = iroh.node.connections().await?;
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
            Self::Connection { node_id } => {
                let conn_info = iroh.node.connection_info(node_id).await?;
                match conn_info {
                    Some(info) => println!("{}", fmt_connection(info)),
                    None => println!("Not Found"),
                }
            }
            Self::Shutdown { force } => {
                iroh.node.shutdown(force).await?;
            }
            Self::Stats => {
                let stats = iroh.node.stats().await?;
                for (name, details) in stats.iter() {
                    println!(
                        "{:23} : {:>6}    ({})",
                        name, details.value, details.description
                    );
                }
            }
            Self::Status => {
                let response = iroh.node.status().await?;
                println!("Listening addresses: {:#?}", response.listen_addrs);
                println!("Node public key: {}", response.addr.node_id);
                println!("Version: {}", response.version);
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
        ["node id", "derp", "conn type", "latency", "last used"]
            .into_iter()
            .map(bold_cell),
    );
    while let Some(Ok(conn_info)) = infos.next().await {
        let node_id: Cell = conn_info.node_id.to_string().into();
        let derp_url = conn_info
            .derp_url
            .map_or(String::new(), |url| url.to_string())
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
        table.add_row([node_id, derp_url, conn_type, latency, last_used]);
    }
    table.to_string()
}

fn fmt_connection(info: ConnectionInfo) -> String {
    let ConnectionInfo {
        id: _,
        node_id,
        derp_url,
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
    let derp_url = derp_url
        .map(|r| r.to_string())
        .unwrap_or_else(|| String::from("unknown"));
    table.add_row([bold_cell("derp url"), derp_url.into()]);
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

    [
        addr.into(),
        fmt_latency(latency).into(),
        last_control,
        last_payload,
    ]
    .into()
}

fn fmt_addrs(addrs: Vec<DirectAddrInfo>) -> comfy_table::Table {
    let mut table = Table::new();
    table.load_preset(NOTHING).set_header(
        vec!["addr", "latency", "last control", "last data"]
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
