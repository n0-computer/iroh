use anyhow::Result;
use futures_lite::Stream;
use futures_util::{SinkExt, StreamExt};
use iroh_net::Endpoint;
use quic_rpc::server::{ChannelTypes, RpcChannel, RpcServerError};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::{form::EntryOrForm, rpc::proto::*, Engine};

fn map_err(err: anyhow::Error) -> RpcError {
    RpcError::new(&*err)
}

impl Engine {
    pub async fn handle_spaces_request<C: ChannelTypes<RpcService>>(
        self,
        endpoint: Endpoint,
        msg: Request,
        chan: RpcChannel<RpcService, C>,
    ) -> Result<(), RpcServerError<C>> {
        use Request::*;
        match msg {
            IngestEntry(msg) => {
                chan.rpc(msg, self, |engine, req| async move {
                    engine
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
                chan.rpc(msg, self, |engine, req| async move {
                    let entry = EntryOrForm::Form(req.entry.into());
                    engine
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
                chan.rpc(msg, self, |engine, req| async move {
                    engine
                        .insert_secret(req.secret)
                        .await
                        .map(|_| InsertSecretResponse)
                        .map_err(map_err)
                })
                .await
            }
            GetEntries(msg) => {
                chan.try_server_streaming(msg, self, |engine, req| async move {
                    let stream = engine
                        .get_entries(req.namespace, req.range)
                        .await
                        .map_err(map_err)?;
                    Ok(stream.map(|res| res.map(GetEntriesResponse).map_err(map_err)))
                })
                .await
            }
            GetEntry(msg) => {
                chan.rpc(msg, self, |engine, req| async move {
                    engine
                        .get_entry(req.namespace, req.subspace, req.path)
                        .await
                        .map(|entry| GetEntryResponse(entry.map(Into::into)))
                        .map_err(map_err)
                })
                .await
            }
            CreateNamespace(msg) => {
                chan.rpc(msg, self, |engine, req| async move {
                    engine
                        .create_namespace(req.kind, req.owner)
                        .await
                        .map(CreateNamespaceResponse)
                        .map_err(map_err)
                })
                .await
            }
            CreateUser(msg) => {
                chan.rpc(msg, self, |engine, _| async move {
                    engine
                        .create_user()
                        .await
                        .map(CreateUserResponse)
                        .map_err(map_err)
                })
                .await
            }
            DelegateCaps(msg) => {
                chan.rpc(msg, self, |engine, req| async move {
                    engine
                        .delegate_caps(req.from, req.access_mode, req.to)
                        .await
                        .map(DelegateCapsResponse)
                        .map_err(map_err)
                })
                .await
            }
            ImportCaps(msg) => {
                chan.rpc(msg, self, |engine, req| async move {
                    engine
                        .import_caps(req.caps)
                        .await
                        .map(|_| ImportCapsResponse)
                        .map_err(map_err)
                })
                .await
            }
            SyncWithPeer(msg) => {
                chan.bidi_streaming(msg, self, |engine, req, update_stream| {
                    // TODO: refactor to use less tasks
                    let (events_tx, events_rx) = tokio::sync::mpsc::channel(32);
                    tokio::task::spawn(async move {
                        if let Err(err) =
                            sync_with_peer(&engine, req, events_tx.clone(), update_stream).await
                        {
                            let _ = events_tx.send(Err(RpcError::new(&*err))).await;
                        }
                    });
                    ReceiverStream::new(events_rx)
                })
                .await
            }
            SyncWithPeerUpdate(_) => Err(RpcServerError::UnexpectedStartMessage),
            Subscribe(msg) => {
                chan.try_server_streaming(msg, self, |engine, req| async move {
                    let (tx, rx) = mpsc::channel(1024);
                    if let Some(progress_id) = req.initial_progress_id {
                        engine
                            .resume_subscription(
                                progress_id,
                                req.namespace,
                                req.area,
                                req.params,
                                tx,
                            )
                            .await
                            .map_err(map_err)?;
                    } else {
                        engine
                            .subscribe_area(req.namespace, req.area, req.params, tx)
                            .await
                            .map_err(map_err)?;
                    }
                    Ok(ReceiverStream::new(rx).map(Ok))
                })
                .await
            }
            Addr(msg) => {
                chan.rpc(msg, endpoint, |endpoint, _req| async move {
                    let addr = endpoint.node_addr().await.map_err(map_err)?;
                    Ok(addr)
                })
                .await
            }
            AddAddr(msg) => {
                chan.rpc(msg, endpoint, |endpoint, req| async move {
                    endpoint.add_node_addr(req.addr).map_err(map_err)?;
                    Ok(())
                })
                .await
            }
        }
    }
}

// TODO: Try to use the streams directly instead of spawning two tasks.
async fn sync_with_peer(
    engine: &Engine,
    req: SyncWithPeerRequest,
    events_tx: mpsc::Sender<RpcResult<SyncWithPeerResponse>>,
    mut update_stream: impl Stream<Item = SyncWithPeerUpdate> + Unpin + Send + 'static,
) -> anyhow::Result<()> {
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
