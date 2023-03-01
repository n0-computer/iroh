mod derp;
// from tailscale/tailcfg/derpmap.go
mod derp_cfg;
mod derp_client;
pub mod derphttp;

pub use derphttp as http;

pub use derp_cfg::{DerpMap, DerpNode, DerpRegion, UseIpv4, UseIpv6};
pub use derp_client::ReceivedMessage;
