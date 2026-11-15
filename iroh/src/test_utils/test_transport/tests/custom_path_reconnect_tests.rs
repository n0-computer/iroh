use super::*;
use n0_future::StreamExt;

#[tokio::test]
async fn custom_path_opens_when_connecting_with_a_cached_ip_path() -> Result<()> {
    let network = TestNetwork::new();
    let client_key = SecretKey::generate();
    let server_key = SecretKey::generate();
    let config = EndpointConfig::default()
        .with_ip()
        .with_custom_bias(TransportBias::primary().with_rtt_advantage(Duration::from_secs(10)));
    let client = endpoint_builder(
        client_key.clone(),
        network.create_transport(client_key.public())?,
        config.clone(),
    )
    .clear_address_lookup()
    .bind()
    .await?;
    let server = endpoint_builder(
        server_key.clone(),
        network.create_transport(server_key.public())?,
        config,
    )
    .clear_address_lookup()
    .bind()
    .await?;
    let router = Router::builder(server.clone())
        .accept(ECHO_ALPN, Echo)
        .spawn();
    let port = server
        .bound_sockets()
        .iter()
        .find(|addr| addr.is_ipv4())
        .unwrap()
        .port();
    let ip = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
    let initial = client
        .connect(EndpointAddr::new(server.id()).with_ip_addr(ip), ECHO_ALPN)
        .await?;
    verify_echo(&initial, b"initial IP connection").await?;
    assert!(
        initial
            .paths()
            .iter()
            .any(|path| path.remote_addr().is_ip())
    );

    // Keep the first connection alive: its selected IP path is cached while the
    // application introduces a preferred custom address on the second dial.
    let next = client
        .connect(custom_only_addr(server.id()), ECHO_ALPN)
        .await?;
    let selected = tokio::time::timeout(Duration::from_secs(2), async {
        let mut paths = next.paths_stream();
        while let Some(snapshot) = paths.next().await {
            if snapshot
                .iter()
                .any(|path| path.is_selected() && path.remote_addr().is_custom())
            {
                return;
            }
        }
        panic!("connection closed before opening its custom path");
    })
    .await;
    assert!(
        selected.is_ok(),
        "custom address remained unopened: {:?}",
        next.paths()
    );
    verify_echo(&next, b"custom connection").await?;
    next.close(0u32.into(), b"done");
    initial.close(0u32.into(), b"done");
    client.close().await;
    router.shutdown().await.anyerr()?;
    Ok(())
}
