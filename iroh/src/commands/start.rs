use std::net::SocketAddr;

use anyhow::Result;
use clap::Args;
use iroh_bytes::{protocol::RequestToken, util::runtime};

use crate::config::NodeConfig;

use super::{blob::BlobAddOptions, node::StartOptions, RequestTokenOptions};

#[derive(Args, Debug, Clone)]
pub struct StartArgs {
    /// Listening address to bind to
    #[clap(long, short, default_value_t = SocketAddr::from(iroh::node::DEFAULT_BIND_ADDR))]
    addr: SocketAddr,
    /// Use a token to authenticate requests for data
    ///
    /// Pass "random" to generate a random token, or base32-encoded bytes to use as a token
    #[clap(long)]
    request_token: Option<RequestTokenOptions>,

    /// Add data when starting the node
    #[clap(flatten)]
    add_options: BlobAddOptions,
}

impl StartArgs {
    fn request_token(&self) -> Option<RequestToken> {
        match self.request_token {
            Some(RequestTokenOptions::Random) => Some(RequestToken::generate()),
            Some(RequestTokenOptions::Token(ref token)) => Some(token.clone()),
            None => None,
        }
    }

    pub async fn run(self, rt: &runtime::Handle, config: &NodeConfig, rpc_port: u16) -> Result<()> {
        let request_token = self.request_token();
        super::node::run(
            rt,
            StartOptions {
                addr: self.addr,
                rpc_port,
                request_token,
                derp_map: config.derp_map()?,
            },
            self.add_options,
        )
        .await
    }
}
