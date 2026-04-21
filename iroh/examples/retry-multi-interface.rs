//! Reproducer for iroh#4114: invalid retry token when listening on multiple
//! interfaces.
//!
//! Binds to both IPv4 and IPv6 (the default for `presets::Minimal`), on all
//! interfaces, so the server sees Initials from the client arriving on
//! different local addresses. When the server's retry filter asks the client
//! to retry, the token is tied to a specific (local, remote) pair; if the
//! retried Initial arrives on a different path than the one the token was
//! issued for, the server currently rejects it with `INVALID_TOKEN`.
//!
//! Relays are disabled on both sides so any connection that comes up is a
//! direct path — making the retry mismatch the only plausible failure mode.
//!
//! This example uses the raw `Endpoint` API (no `Router`) to keep the retry
//! dance visible.
//!
//! ## Usage
//!
//! On one machine:
//! ```sh
//! cargo run --example retry-multi-interface -- accept
//! ```
//!
//! It prints an `EndpointTicket`. On another machine:
//! ```sh
//! cargo run --example retry-multi-interface -- connect <TICKET>
//! ```
//!
//! Run with `RUST_LOG=iroh=debug,noq=debug` to see the Initial/Retry/Initial
//! exchange. If the bug reproduces, the second Initial is rejected with an
//! `INVALID_TOKEN` frame and the dial fails.
use clap::{Parser, Subcommand};
use iroh::{Endpoint, EndpointAddr, RelayMode, endpoint::presets};
use iroh_tickets::endpoint::EndpointTicket;
use n0_error::{AnyError as Error, Result, StdResultExt};

const ALPN: &[u8] = b"iroh-example/retry-multi-interface/0";

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the accept side and print its `EndpointTicket`.
    Accept,
    /// Dial the `EndpointTicket` printed by the accept side.
    Connect { ticket: EndpointTicket },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    match Cli::parse().cmd {
        Cmd::Accept => accept().await,
        Cmd::Connect { ticket } => connect(ticket).await,
    }
}

async fn accept() -> Result<()> {
    // `presets::Minimal` binds to both the default IPv4 and IPv6 transports,
    // so on multi-homed hosts we will advertise and receive on multiple
    // local addresses.
    let endpoint = Endpoint::builder(presets::Minimal)
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;

    let ticket = EndpointTicket::new(endpoint.addr());
    println!("Endpoint ID:    {}", endpoint.id());
    println!("Bound sockets:  {:?}", endpoint.bound_sockets());
    println!();
    println!("Ticket (copy this to the connect side):");
    println!();
    println!("    {ticket}");
    println!();

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            let remote_addr = incoming.remote_addr().clone();
            if incoming.remote_addr_validated() {
                println!("accept: validated incoming from {remote_addr:?}, accepting");
                let conn = match incoming.accept() {
                    Ok(accepting) => accepting.await.anyerr()?,
                    Err(e) => {
                        println!("accept: failed to accept: {e:?}");
                        return Ok::<_, Error>(());
                    }
                };
                let (mut send, mut recv) = conn.accept_bi().await.anyerr()?;
                let n = tokio::io::copy(&mut recv, &mut send).await.anyerr()?;
                println!("accept: echoed {n} bytes");
                send.finish().anyerr()?;
                conn.closed().await;
            } else {
                println!("accept: unvalidated incoming from {remote_addr:?}, sending retry");
                if let Err(e) = incoming.retry() {
                    println!("accept: retry failed: {e:?}");
                }
            }
            Ok::<_, Error>(())
        });
    }
    Ok(())
}

async fn connect(ticket: EndpointTicket) -> Result<()> {
    let endpoint = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;
    println!("connect: local sockets: {:?}", endpoint.bound_sockets());

    let addr: EndpointAddr = ticket.into();
    println!("connect: dialing {addr:?}");
    let conn = match endpoint.connect(addr, ALPN).await {
        Ok(conn) => conn,
        Err(e) => {
            // Print the full error chain so INVALID_TOKEN / ConnectionError
            // variants are visible when the retry-token mismatch bug bites.
            println!("connect: dial failed: {e:#}");
            return Err(e.into());
        }
    };
    println!("connect: connected, opening stream");

    let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
    send.write_all(b"hello retry").await.anyerr()?;
    send.finish().anyerr()?;
    let response = recv.read_to_end(1024).await.anyerr()?;
    println!("connect: got response: {:?}", std::str::from_utf8(&response));

    conn.close(0u32.into(), b"bye");
    endpoint.close().await;
    Ok(())
}
