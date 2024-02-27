fn main() {
    unimplemented!()
}
// use anyhow::Result;
// use ed25519_dalek::SigningKey;
// use iroh_dns::{packet::NodeAnnounce};
// use iroh_net::key::SecretKey;
// use url::Url;
//
// #[tokio::main]
// async fn main() -> Result<()> {
//     tracing_subscriber::fmt::init();
//     let node_secret = SecretKey::generate();
//     let signing_key = SigningKey::from_bytes(&node_secret.to_bytes());
//     let node_id = node_secret.public();
//
//     println!("node_id {}", node_id);
//
//     let home_derp: Url = "https://derp.example".parse()?;
//     let msg = NodeAnnounce {
//         node_id,
//         home_derp: Some(home_derp.clone()),
//         home_dns: Default::default(),
//     };
//
//     // let name_server: SocketAddr = "127.0.0.1:5353".parse()?;
//     // let res = publish_dns_sig0(name_server, msg, signing_key).await;
//     let url: Url = "http://localhost:8080".parse()?;
//     let res = sig0::publish_https(url, msg, signing_key).await;
//     println!("res {res:?}");
//     res
// }
// mod sig0 {
//
//     use std::{net::SocketAddr, str::FromStr, time::UNIX_EPOCH};
//
//     use anyhow::{anyhow, bail, Result};
//     use hickory_client::{
//         client::{Client, ClientHandle, SyncClient},
//         op::ResponseCode,
//         proto::rr::dnssec::{Algorithm, KeyPair, SigSigner},
//         rr::{rdata::key::KEY, Name},
//         udp::UdpClientConnection,
//     };
//     use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
//     use reqwest::header::CONTENT_TYPE;
//     use ring::signature::Ed25519KeyPair;
//     use tracing::debug;
//     use url::Url;
//
//     use iroh_dns::packet::NodeAnnounce;
//
//     pub async fn publish_https(
//         mut url: Url,
//         announce: NodeAnnounce,
//         signing_key: ed25519_dalek::SigningKey,
//     ) -> Result<()> {
//         let public_key = signing_key.verifying_key();
//         let node_zone = create_node_zone_name(public_key)?;
//         let mut message = announce.into_hickory_update_message()?;
//         println!("message {message:?}");
//         let signer = create_sig0_signer(signing_key, node_zone.clone())?;
//         let ts = get_now_timestamp()?;
//         // if signer.should_finalize_message(&message) {
//         match message.finalize(&signer, ts) {
//             Ok(_answer_verifier) => {}
//             Err(e) => {
//                 debug!("could not sign message: {}", e);
//                 bail!(e)
//             }
//         }
//         // }
//         let body = message.to_bytes()?;
//
//         url.set_path("/dns-query");
//         let client = reqwest::Client::new();
//         let res = client
//             .post(url)
//             .body(body)
//             .header(CONTENT_TYPE, "application/dns-message")
//             .send()
//             .await?;
//         let headers = res.headers().clone();
//         let body = res.bytes().await?;
//         let parsed = hickory_proto::op::Message::from_bytes(&body)?;
//         println!("headers {headers:#?}");
//         println!("body {parsed:#?}");
//
//         Ok(())
//     }
//
//     fn get_now_timestamp() -> Result<u32> {
//         let now = match std::time::SystemTime::now().duration_since(UNIX_EPOCH) {
//             Ok(now) => now.as_secs(),
//             Err(_) => bail!("Current time is before the Unix epoch."),
//         };
//
//         // TODO: truncates u64 to u32, error on overflow?
//         let now = now as u32;
//         Ok(now)
//     }
//
//     pub fn create_node_zone_name(public_key: ed25519_dalek::VerifyingKey) -> Result<Name> {
//         let node_id_str = iroh_base::base32::fmt(public_key.as_bytes());
//         let node_zone = Name::from_str(&format!("{}.", node_id_str))?;
//         Ok(node_zone)
//     }
//
//     pub async fn publish_dns_sig0(
//         nameserver: SocketAddr,
//         announce: NodeAnnounce,
//         signing_key: ed25519_dalek::SigningKey,
//     ) -> Result<()> {
//         let public_key = signing_key.verifying_key();
//         let record = announce.into_hickory_dns_record()?;
//         let node_zone = create_node_zone_name(public_key)?;
//
//         let signer = create_sig0_signer(signing_key, node_zone.clone())?;
//
//         // TODO: HttpsClientConnection silently ignores the signer, there's a TODO in the
//         // hickory-client code...
//         // let conn = {
//         //     let client_config = insecure_client_config();
//         //     let name_server: SocketAddr = "127.0.0.1:8443".parse()?;
//         //     let dns_name = "localhost".to_string();
//         //     let conn: HttpsClientConnection<AsyncIoTokioAsStd<tokio::net::TcpStream>> =
//         //         HttpsClientConnection::new(name_server, dns_name, client_config);
//         //     conn
//         // };
//
//         let conn = UdpClientConnection::new(nameserver)?;
//         let mut client = {
//             let client = SyncClient::with_signer(conn, signer);
//             let (client, bg) = client.new_future().await?;
//             tokio::task::spawn(bg);
//             client
//         };
//
//         // Create the record.
//         let result = client.create(record, node_zone).await?;
//         match result.response_code() {
//             ResponseCode::NoError => Ok(()),
//             code @ _ => Err(anyhow!("request failed: {code}")),
//         }
//     }
//
//     fn create_sig0_signer(signing_key: ed25519_dalek::SigningKey, zone: Name) -> Result<SigSigner> {
//         // Create the Hickory DNS SIG(0) signing facility. Generally the signer_name is the label
//         //  associated with KEY record in the server.
//         let public_key = signing_key.verifying_key();
//         let key = Ed25519KeyPair::from_seed_and_public_key(
//             &signing_key.to_bytes(),
//             public_key.as_bytes(),
//         )?;
//         let key = KeyPair::from_ed25519(key);
//         // Create the RData KEY associated with the key. This example uses defaults for all the
//         //  KeyTrust, KeyUsage, UpdateScope, Protocol. Many of these have been deprecated in current
//         //  DNS RFCs, but are still supported by many servers for auth. See auth docs of the remote
//         //  server for help in understanding it's requirements and support of these options.
//         let sig0key = KEY::new(
//             Default::default(),
//             Default::default(),
//             Default::default(),
//             Default::default(),
//             Algorithm::ED25519,
//             key.to_public_bytes()?,
//         );
//         Ok(SigSigner::sig0(sig0key, key, zone))
//     }
//
//     // fn insecure_client_config() -> Arc<ClientConfig> {
//     //     let crypto = rustls::ClientConfig::builder()
//     //         .with_safe_defaults()
//     //         .with_custom_certificate_verifier(SkipServerVerification::new())
//     //         .with_no_client_auth();
//     //     Arc::new(crypto)
//     // }
//     // /// Dummy certificate verifier that treats any certificate as valid.
//     // /// NOTE, such verification is vulnerable to MITM attacks, but convenient for testing.
//     // struct SkipServerVerification;
//     //
//     // impl SkipServerVerification {
//     //     fn new() -> Arc<Self> {
//     //         Arc::new(Self)
//     //     }
//     // }
//     //
//     // impl rustls::client::ServerCertVerifier for SkipServerVerification {
//     //     fn verify_server_cert(
//     //         &self,
//     //         _end_entity: &rustls::Certificate,
//     //         _intermediates: &[rustls::Certificate],
//     //         _server_name: &rustls::ServerName,
//     //         _scts: &mut dyn Iterator<Item = &[u8]>,
//     //         _ocsp_response: &[u8],
//     //         _now: std::time::SystemTime,
//     //     ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
//     //         Ok(rustls::client::ServerCertVerified::assertion())
//     //     }
//     // }
// }
