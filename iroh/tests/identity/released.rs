//! Run with IROH_RELEASED_IDENTITY_PEER pointing to the separately built 1.1.0 peer.

use std::{process::Stdio, sync::Arc, time::Duration};

use iroh::identity::{EndpointAddr, IdentityEndpoint, LocalIdentity, PeerId, Registry};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
};

const ALPN: &[u8] = b"released-identity-test/1";

#[tokio::test]
#[n0_tracing_test::traced_test]
#[ignore = "requires the separately built released-peer binary; see tests/identity/README.md"]
async fn ed25519_interoperates_with_released_iroh_1_1_in_both_directions() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let binary =
            std::env::var_os("IROH_RELEASED_IDENTITY_PEER").expect("set released peer binary path");
        let registry = Arc::new(Registry::builtins(vec![1, 2]).unwrap());
        let identity =
            LocalIdentity::ed25519(iroh::SecretKey::from_bytes(&[88; 32]), &registry).unwrap();
        let endpoint = IdentityEndpoint::builder(identity, registry)
            .bind_addr("127.0.0.1:0".parse().unwrap())
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let expected = PeerId::Legacy(iroh::SecretKey::from_bytes(&[77; 32]).public());
        for mode in ["server", "client"] {
            let mut command = Command::new(&binary);
            command
                .arg(mode)
                .kill_on_drop(true)
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit());
            if mode == "client" {
                command
                    .arg(endpoint.id().to_string())
                    .arg(endpoint.local_addr().unwrap().to_string());
            }
            let mut child = command.spawn().unwrap();
            let stdout = child.stdout.take().unwrap();
            let mut lines = BufReader::new(stdout).lines();
            let line = lines.next_line().await.unwrap().expect("released contact");
            let (id, addr) = line.split_once(' ').unwrap();
            assert_eq!(id.parse::<PeerId>().unwrap(), expected);
            let connection = if mode == "server" {
                endpoint
                    .connect(EndpointAddr::new(expected, addr.parse().unwrap()), ALPN)
                    .await
                    .unwrap()
            } else {
                endpoint.accept().await.unwrap()
            };
            assert_eq!(connection.remote_id(), expected);
            if mode == "server" {
                let (mut send, mut recv) = connection.open_bi().await.unwrap();
                send.write_all(b"new endpoint with legacy identity")
                    .await
                    .unwrap();
                send.finish().unwrap();
                assert_eq!(
                    recv.read_to_end(128).await.unwrap(),
                    b"new endpoint with legacy identity"
                );
            } else {
                let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                let data = recv.read_to_end(128).await.unwrap();
                send.write_all(&data).await.unwrap();
                send.finish().unwrap();
                // The released client verifies the echo, then closes its endpoint.
                // Its successful exit below is the application-level acknowledgement.
                let _ = send.stopped().await;
            }
            assert!(child.wait().await.unwrap().success());
        }
        endpoint.close().await;
    })
    .await
    .expect("released interop timeout");
}
