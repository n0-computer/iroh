#[macro_export]
macro_rules! impl_serve {
    ($label:ident, $server:ty, $req:ty, $resp:ty) => {
        paste::paste! {
            pub type [<$label ServerAddr>] = $crate::Addr<
                $crate::tarpc::ClientMessage<$req>, $crate::tarpc::Response<$resp>
            >;

            pub async fn serve(
                server_addr: [<$label ServerAddr>],
                server: $server,
            ) -> anyhow::Result<()> {
                match server_addr {
                    $crate::Addr::Tcp(server_addr) => serve_tcp(server_addr, server).await,
                    #[cfg(unix)]
                    $crate::Addr::Uds(server_addr) => todo!(),
                    $crate::Addr::Mem(chan) => serve_mem(chan, server).await,
                }
            }

            async fn serve_tcp(
                server_addr: std::net::SocketAddr,
                server: $server,
            ) -> anyhow::Result<()> {
                use futures::{Sink, StreamExt};
                use $crate::tarpc::server::{incoming::Incoming, Channel};
                use iroh_rpc_types::[<$label:snake>]::$label;
                use $crate::bincode::Options;

                // TODO: configurable
                let max_channels_per_ip = 500;
                let max_channels = 500;

                let mut listener = $crate::tarpc::serde_transport::tcp::listen(
                    &server_addr,
                    || $crate::tarpc::tokio_serde::formats::Bincode::from($crate::bincode::options().with_no_limit()),
                )
                    .await?;
                listener.config_mut().max_frame_length(usize::MAX);
                listener
                // Ignore accept errors.
                    .filter_map(|r| futures::future::ready(r.ok()))
                    .map($crate::tarpc::server::BaseChannel::with_defaults)
                // Limit channels  per IP.
                    .max_channels_per_key(max_channels_per_ip, |t| {
                        t.transport().peer_addr().unwrap().ip()
                    })
                    .map(|channel| {
                        // let server = S::new_tcp(&channel);
                        let server = server.clone();
                        channel.execute(server.serve())
                    })
                    .buffer_unordered(max_channels)
                    .for_each(|_| async {})
                    .await;

                Ok(())
            }

            async fn serve_mem(
                server_transport: $crate::Channel<$crate::tarpc::ClientMessage<$req>, $crate::tarpc::Response<$resp>>,
                server: $server,
            ) -> anyhow::Result<()> {
                use $crate::tarpc::server::Channel;
                use $crate::tarpc::server::Serve;
                use iroh_rpc_types::[<$label:snake>]::$label;

                let transport = $crate::tarpc::server::BaseChannel::with_defaults(server_transport);
                let t = server.serve();
                transport.execute(|a, b| t.serve(a, b)).await;
                Ok(())
            }
        }
    };
}
