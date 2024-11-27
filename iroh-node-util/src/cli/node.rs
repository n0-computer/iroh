//! Node commands
use clap::Subcommand;

use crate::rpc::client::node;

/// Commands to manage the iroh RPC.
#[derive(Subcommand, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum NodeCommands {
    /// Get statistics and metrics from the running node.
    Stats,
    /// Get status of the running node.
    Status,
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
    /// Run the RPC command given the iroh client and the console environment.
    pub async fn run(self, node: &node::Client) -> anyhow::Result<()> {
        match self {
            Self::Stats => {
                let stats = node.stats().await?;
                for (name, details) in stats.iter() {
                    println!(
                        "{:23} : {:>6}    ({})",
                        name, details.value, details.description
                    );
                }
                Ok(())
            }
            Self::Shutdown { force } => {
                node.shutdown(force).await?;
                Ok(())
            }
            Self::Status => {
                let response = node.status().await?;
                println!("Listening addresses: {:#?}", response.listen_addrs);
                println!("Node ID: {}", response.addr.node_id);
                println!("Version: {}", response.version);
                if let Some(addr) = response.rpc_addr {
                    println!("RPC Addr: {}", addr);
                }
                Ok(())
            }
        }
    }
}
