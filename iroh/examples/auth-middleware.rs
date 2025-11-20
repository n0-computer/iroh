//! Implementation of authentication using iroh middlewares
//!
//! This implements an auth protocol that works with iroh middlewares.
//! It allows to put authentication in front of iroh protocols. The protocols don't need any special support.
//! Authentication is handled prior to establishing the connections, over a separate connection.

use iroh::{Endpoint, EndpointAddr, protocol::Router};
use n0_error::{Result, StdResultExt};

use crate::echo::Echo;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let server_router = accept_side(b"secret!!").await?;
    server_router.endpoint().online().await;
    let server_addr = server_router.endpoint().addr();

    println!("-- no --");
    let res = connect_side_no_auth(server_addr.clone()).await;
    println!("echo without auth: {:#}", res.unwrap_err());

    println!("-- wrong --");
    let res = connect_side(server_addr.clone(), b"dunno").await;
    println!("echo with wrong auth: {:#}", res.unwrap_err());

    println!("-- correct --");
    let res = connect_side(server_addr.clone(), b"secret!!").await;
    println!("echo with correct auth: {res:?}");

    server_router.shutdown().await.anyerr()?;

    Ok(())
}

async fn connect_side(remote_addr: EndpointAddr, token: &[u8]) -> Result<()> {
    let (auth_middleware, auth_connector) = auth::connect(token.to_vec());
    let endpoint = Endpoint::builder()
        .middleware(auth_middleware)
        .bind()
        .await?;
    let _guard = auth_connector.spawn(endpoint.clone());
    Echo::connect(&endpoint, remote_addr, b"hello there!").await
}

async fn connect_side_no_auth(remote_addr: EndpointAddr) -> Result<()> {
    let endpoint = Endpoint::bind().await?;
    Echo::connect(&endpoint, remote_addr, b"hello there!").await
}

async fn accept_side(token: &[u8]) -> Result<Router> {
    let (auth_middleware, auth_protocol) = auth::accept(token.to_vec());
    let endpoint = Endpoint::builder()
        .middleware(auth_middleware)
        .bind()
        .await?;

    let router = Router::builder(endpoint)
        .accept(auth::ALPN, auth_protocol)
        .accept(echo::ALPN, Echo)
        .spawn();

    Ok(router)
}

mod echo {
    //! A bare-bones protocol with no knowledge of auth whatsoever.

    use iroh::{
        Endpoint, EndpointAddr,
        endpoint::Connection,
        protocol::{AcceptError, ProtocolHandler},
    };
    use n0_error::{Result, StdResultExt, anyerr};

    #[derive(Debug, Clone)]
    pub struct Echo;

    pub const ALPN: &[u8] = b"iroh-example/echo/0";

    impl Echo {
        pub async fn connect(
            endpoint: &Endpoint,
            remote: impl Into<EndpointAddr>,
            message: &[u8],
        ) -> Result<()> {
            let conn = endpoint.connect(remote, ALPN).await?;
            let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
            send.write_all(message).await.anyerr()?;
            send.finish().anyerr()?;
            let response = recv.read_to_end(1000).await.anyerr()?;
            conn.close(0u32.into(), b"bye!");
            if response == message {
                Ok(())
            } else {
                Err(anyerr!("Received invalid response"))
            }
        }
    }

    impl ProtocolHandler for Echo {
        async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
            let (mut send, mut recv) = connection.accept_bi().await?;
            tokio::io::copy(&mut recv, &mut send).await?;
            send.finish()?;
            connection.closed().await;
            Ok(())
        }
    }
}

mod auth {
    //! Authentication middleware

    use std::{
        collections::{HashMap, HashSet, hash_map},
        sync::{Arc, Mutex},
    };

    use iroh::{
        Endpoint, EndpointAddr, EndpointId,
        endpoint::{AfterHandshakeOutcome, BeforeConnectOutcome, Connection, Middleware},
        protocol::{AcceptError, ProtocolHandler},
    };
    use n0_error::{AnyError, Result, StackResultExt, StdResultExt, anyerr};
    use n0_future::task::AbortOnDropHandle;
    use quinn::ConnectionError;
    use tokio::{
        sync::{mpsc, oneshot},
        task::JoinSet,
    };
    use tracing::debug;

    pub const ALPN: &[u8] = b"iroh-example/auth/0";

    const CLOSE_ACCEPTED: u32 = 1;
    const CLOSE_DENIED: u32 = 403;

    /// Connect side: Use this if you want to pre-auth outgoing connections.
    pub fn connect(token: Vec<u8>) -> (AuthConnectMiddleware, AuthConnectTask) {
        let (tx, rx) = mpsc::channel(16);
        let middleware = AuthConnectMiddleware { tx };
        let connector = AuthConnectTask {
            token,
            rx,
            allowed_remotes: Default::default(),
            pending_remotes: Default::default(),
            tasks: JoinSet::new(),
        };
        (middleware, connector)
    }

    /// Middleware to mount on the endpoint builder.
    #[derive(Debug)]
    pub struct AuthConnectMiddleware {
        tx: mpsc::Sender<(EndpointId, oneshot::Sender<Result<(), Arc<AnyError>>>)>,
    }

    impl AuthConnectMiddleware {
        async fn authenticate(&self, remote_id: EndpointId) -> Result<()> {
            let (tx, rx) = oneshot::channel();
            self.tx
                .send((remote_id, tx))
                .await
                .std_context("authenticator stopped")?;
            rx.await
                .std_context("authenticator stopped")?
                .context("failed to authenticate")
        }
    }

    impl Middleware for AuthConnectMiddleware {
        async fn before_connect<'a>(
            &'a self,
            remote_addr: &'a EndpointAddr,
            alpn: &'a [u8],
        ) -> BeforeConnectOutcome {
            // Don't intercept auth request themsevles
            if alpn == ALPN {
                BeforeConnectOutcome::Accept
            } else {
                match self.authenticate(remote_addr.id).await {
                    Ok(()) => BeforeConnectOutcome::Accept,
                    Err(err) => {
                        debug!("authentication denied: {err:#}");
                        BeforeConnectOutcome::Reject
                    }
                }
            }
        }
    }

    /// Connector task that initiates pre-auth request. Call [`Self::spawn`] once the endpoint is built.
    pub struct AuthConnectTask {
        token: Vec<u8>,
        rx: mpsc::Receiver<(EndpointId, oneshot::Sender<Result<(), Arc<AnyError>>>)>,
        allowed_remotes: HashSet<EndpointId>,
        pending_remotes: HashMap<EndpointId, Vec<oneshot::Sender<Result<(), Arc<AnyError>>>>>,
        tasks: JoinSet<(EndpointId, Result<()>)>,
    }

    impl AuthConnectTask {
        pub fn spawn(self, endpoint: Endpoint) -> AbortOnDropHandle<()> {
            AbortOnDropHandle::new(tokio::spawn(self.run(endpoint)))
        }

        async fn run(mut self, endpoint: Endpoint) {
            loop {
                tokio::select! {
                    msg = self.rx.recv() => {
                        let Some((remote_id, tx)) = msg else {
                            break;
                        };
                        self.handle_msg(&endpoint, remote_id, tx);
                    }
                    Some(res) = self.tasks.join_next(), if !self.tasks.is_empty() => {
                        let (remote_id, res) = res.expect("connect task panicked");
                        let res = res.map_err(Arc::new);
                        self.handle_task(remote_id, res);
                    }
                }
            }
        }

        fn handle_msg(
            &mut self,
            endpoint: &Endpoint,
            remote_id: EndpointId,
            tx: oneshot::Sender<Result<(), Arc<AnyError>>>,
        ) {
            if self.allowed_remotes.contains(&remote_id) {
                tx.send(Ok(())).ok();
            } else {
                match self.pending_remotes.entry(remote_id) {
                    hash_map::Entry::Occupied(mut entry) => {
                        entry.get_mut().push(tx);
                    }
                    hash_map::Entry::Vacant(entry) => {
                        let endpoint = endpoint.clone();
                        let token = self.token.clone();
                        self.tasks.spawn(async move {
                            let res = Self::connect(endpoint, remote_id, token).await;
                            (remote_id, res)
                        });
                        entry.insert(vec![tx]);
                    }
                }
            }
        }

        fn handle_task(&mut self, remote_id: EndpointId, res: Result<(), Arc<AnyError>>) {
            if res.is_ok() {
                self.allowed_remotes.insert(remote_id);
            }
            let senders = self.pending_remotes.remove(&remote_id);
            for tx in senders.into_iter().flatten() {
                tx.send(res.clone()).ok();
            }
        }

        async fn connect(endpoint: Endpoint, remote_id: EndpointId, token: Vec<u8>) -> Result<()> {
            let conn = endpoint.connect(remote_id, ALPN).await?;
            let mut stream = conn.open_uni().await.anyerr()?;
            stream.write_all(&token).await.anyerr()?;
            stream.finish().anyerr()?;
            let reason = conn.closed().await;
            if let ConnectionError::ApplicationClosed(code) = &reason
                && code.error_code.into_inner() as u32 == CLOSE_ACCEPTED
            {
                Ok(())
            } else if let ConnectionError::ApplicationClosed(code) = &reason
                && code.error_code.into_inner() as u32 == CLOSE_DENIED
            {
                Err(anyerr!("authentication denied by remote"))
            } else {
                Err(AnyError::from_std(reason))
            }
        }
    }

    /// Accept side: Use this if you want to only accept connections from peers with successful pre-auth requests.
    pub fn accept(token: Vec<u8>) -> (AuthAcceptMiddleware, AuthProtocol) {
        let allowed_remotes: Arc<Mutex<HashSet<EndpointId>>> = Default::default();
        let middleware = AuthAcceptMiddleware {
            allowed_remotes: allowed_remotes.clone(),
        };
        let protocol = AuthProtocol {
            allowed_remotes,
            token,
        };
        (middleware, protocol)
    }

    /// Accept-side auth middleware: Mount this onto the endpoint.
    ///
    /// This will reject incoming connections if the remote did not successfully authenticate before.
    #[derive(Debug)]
    pub struct AuthAcceptMiddleware {
        allowed_remotes: Arc<Mutex<HashSet<EndpointId>>>,
    }

    impl Middleware for AuthAcceptMiddleware {
        async fn after_handshake<'a>(
            &'a self,
            conn: &'a iroh::endpoint::ConnectionInfo,
        ) -> AfterHandshakeOutcome {
            if conn.alpn() == ALPN
                || self
                    .allowed_remotes
                    .lock()
                    .expect("poisoned")
                    .contains(conn.remote_id())
            {
                AfterHandshakeOutcome::Accept
            } else {
                AfterHandshakeOutcome::Reject {
                    error_code: 403u32.into(),
                    reason: b"not authenticated".to_vec(),
                }
            }
        }
    }

    /// Accept-side auth protocol. Mount this on the router to accept authentication requests.
    #[derive(Debug, Clone)]
    pub struct AuthProtocol {
        token: Vec<u8>,
        allowed_remotes: Arc<Mutex<HashSet<EndpointId>>>,
    }

    impl ProtocolHandler for AuthProtocol {
        /// The `accept` method is called for each incoming connection for our ALPN.
        ///
        /// The returned future runs on a newly spawned tokio task, so it can run as long as
        /// the connection lasts.
        async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
            let mut stream = connection.accept_uni().await?;
            let token = stream.read_to_end(256).await.anyerr()?;
            let remote_id = connection.remote_id();
            if token == self.token {
                self.allowed_remotes
                    .lock()
                    .expect("poisoned")
                    .insert(remote_id);
                connection.close(CLOSE_ACCEPTED.into(), b"accepted");
            } else {
                connection.close(CLOSE_DENIED.into(), b"rejected");
            }
            Ok(())
        }
    }
}
