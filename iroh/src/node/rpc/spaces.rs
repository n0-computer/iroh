use anyhow::Result;
use futures_lite::Stream;
use futures_util::SinkExt;
use futures_util::StreamExt;
use iroh_base::rpc::{RpcError, RpcResult};
use iroh_blobs::store::Store;
use iroh_willow::form::EntryOrForm;
use quic_rpc::server::{RpcChannel, RpcServerError};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::node::IrohServerEndpoint;
use crate::rpc_protocol::spaces::*;
use crate::rpc_protocol::RpcService;

use super::Handler;

fn map_err(err: anyhow::Error) -> RpcError {
    RpcError::from(err)
}

impl<D: Store> Handler<D> {
    pub(crate) async fn handle_spaces_request(
        self,
        msg: Request,
        chan: RpcChannel<RpcService, IrohServerEndpoint>,
    ) -> Result<(), RpcServerError<IrohServerEndpoint>> {
        use Request::*;
        match msg {
            IngestEntry(msg) => {
                chan.rpc(msg, self, |handler, req| async move {
                    handler
                        .spaces()?
                        .ingest_entry(req.authorised_entry)
                        .await
                        .map(|inserted| {
                            if inserted {
                                IngestEntrySuccess::Inserted
                            } else {
                                IngestEntrySuccess::Obsolete
                            }
                        })
                        .map_err(map_err)
                })
                .await
            }
            InsertEntry(msg) => {
                chan.rpc(msg, self, |handler, req| async move {
                    let entry = EntryOrForm::Form(req.entry.into());
                    handler
                        .spaces()?
                        .insert_entry(entry, req.auth)
                        .await
                        .map(|(entry, inserted)| {
                            if inserted {
                                InsertEntrySuccess::Inserted(entry)
                            } else {
                                InsertEntrySuccess::Obsolete
                            }
                        })
                        .map_err(map_err)
                })
                .await
            }
            InsertSecret(msg) => {
                chan.rpc(msg, self, |handler, req| async move {
                    handler
                        .spaces()?
                        .insert_secret(req.secret)
                        .await
                        .map(|_| InsertSecretResponse)
                        .map_err(map_err)
                })
                .await
            }
            GetEntries(msg) => {
                chan.try_server_streaming(msg, self, |handler, req| async move {
                    let stream = handler
                        .spaces()?
                        .get_entries(req.namespace, req.range)
                        .await
                        .map_err(map_err)?;
                    Ok(stream.map(|res| res.map(GetEntriesResponse).map_err(map_err)))
                })
                .await
            }
            GetEntry(msg) => {
                chan.rpc(msg, self, |handler, req| async move {
                    handler
                        .spaces()?
                        .get_entry(req.namespace, req.subspace, req.path)
                        .await
                        .map(|entry| GetEntryResponse(entry.map(Into::into)))
                        .map_err(map_err)
                })
                .await
            }
            CreateNamespace(msg) => {
                chan.rpc(msg, self, |handler, req| async move {
                    handler
                        .spaces()?
                        .create_namespace(req.kind, req.owner)
                        .await
                        .map(CreateNamespaceResponse)
                        .map_err(map_err)
                })
                .await
            }
            CreateUser(msg) => {
                chan.rpc(msg, self, |handler, _| async move {
                    handler
                        .spaces()?
                        .create_user()
                        .await
                        .map(CreateUserResponse)
                        .map_err(map_err)
                })
                .await
            }
            DelegateCaps(msg) => {
                chan.rpc(msg, self, |handler, req| async move {
                    handler
                        .spaces()?
                        .delegate_caps(req.from, req.access_mode, req.to)
                        .await
                        .map(DelegateCapsResponse)
                        .map_err(map_err)
                })
                .await
            }
            ImportCaps(msg) => {
                chan.rpc(msg, self, |handler, req| async move {
                    handler
                        .spaces()?
                        .import_caps(req.caps)
                        .await
                        .map(|_| ImportCapsResponse)
                        .map_err(map_err)
                })
                .await
            }
            SyncWithPeer(msg) => {
                chan.bidi_streaming(msg, self, |handler, req, update_stream| {
                    // TODO: refactor to use less tasks
                    let (events_tx, events_rx) = tokio::sync::mpsc::channel(32);
                    tokio::task::spawn(async move {
                        if let Err(err) =
                            sync_with_peer(handler, req, events_tx.clone(), update_stream).await
                        {
                            let _ = events_tx.send(Err(err.into())).await;
                        }
                    });
                    ReceiverStream::new(events_rx)
                })
                .await
            }
            SyncWithPeerUpdate(_) => Err(RpcServerError::UnexpectedStartMessage),
        }
    }
}

// TODO: Try to use the streams directly instead of spawning two tasks.
async fn sync_with_peer<D: Store>(
    handler: Handler<D>,
    req: SyncWithPeerRequest,
    events_tx: mpsc::Sender<RpcResult<SyncWithPeerResponse>>,
    mut update_stream: impl Stream<Item = SyncWithPeerUpdate> + Unpin + Send + 'static,
) -> anyhow::Result<()> {
    let engine = handler.spaces()?;
    let handle = engine
        .sync_with_peer(req.peer, req.init)
        .await
        .map_err(map_err)?;
    let (mut update_sink, mut events) = handle.split();
    tokio::task::spawn(async move {
        while let Some(update) = update_stream.next().await {
            if update_sink.send(update.0).await.is_err() {
                break;
            }
        }
    });
    tokio::task::spawn(async move {
        while let Some(event) = events.next().await {
            if events_tx
                .send(Ok(SyncWithPeerResponse::Event(event.into())))
                .await
                .is_err()
            {
                break;
            }
        }
    });
    Ok(())
}
