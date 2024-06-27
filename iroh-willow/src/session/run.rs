use futures_lite::StreamExt;
use strum::IntoEnumIterator;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error_span, trace, warn};

use crate::{
    proto::sync::{ControlIssueGuarantee, LogicalChannel, Message},
    session::{
        channels::LogicalChannelReceivers,
        pai::{PaiFinder, ToPai},
        Error, Session,
    },
    store::{traits::Storage, Store},
    util::{channel::Receiver, stream::Cancelable},
};

use super::{
    channels::ChannelReceivers,
    data::{DataReceiver, DataSender},
    reconciler::Reconciler,
    SessionMode,
};

const INITIAL_GUARANTEES: u64 = u64::MAX;

impl Session {
    pub async fn run<S: Storage>(
        self,
        store: Store<S>,
        recv: ChannelReceivers,
        cancel_token: CancellationToken,
    ) -> Result<(), Error> {
        let ChannelReceivers {
            control_recv,
            logical_recv:
                LogicalChannelReceivers {
                    reconciliation_recv,
                    static_tokens_recv,
                    capability_recv,
                    aoi_recv,
                    data_recv,
                    intersection_recv,
                },
        } = recv;

        // Make all our receivers close once the cancel_token is triggered.
        let control_recv = Cancelable::new(control_recv, cancel_token.clone());
        let reconciliation_recv = Cancelable::new(reconciliation_recv, cancel_token.clone());
        let intersection_recv = Cancelable::new(intersection_recv, cancel_token.clone());
        let mut static_tokens_recv = Cancelable::new(static_tokens_recv, cancel_token.clone());
        let mut capability_recv = Cancelable::new(capability_recv, cancel_token.clone());
        let mut aoi_recv = Cancelable::new(aoi_recv, cancel_token.clone());
        let mut data_recv = Cancelable::new(data_recv, cancel_token.clone());

        // Setup the private area intersection finder.
        let pai_finder = PaiFinder::new(self.clone(), store.clone());
        let (to_pai_tx, to_pai_rx) = flume::bounded(128);
        self.spawn(error_span!("pai"), {
            move |_session| async move { pai_finder.run(to_pai_rx, intersection_recv).await }
        });

        // Spawn a task to handle incoming static tokens.
        self.spawn(error_span!("stt"), move |session| async move {
            while let Some(message) = static_tokens_recv.try_next().await? {
                session.on_setup_bind_static_token(message);
            }
            Ok(())
        });

        // Only setup data receiver if session is configured in live mode.
        if self.mode() == SessionMode::Live {
            self.spawn(error_span!("dat:r"), {
                let store = store.clone();
                move |session| async move {
                    let mut data_receiver = DataReceiver::new(session, store);
                    while let Some(message) = data_recv.try_next().await? {
                        data_receiver.on_message(message).await?;
                    }
                    Ok(())
                }
            });
            self.spawn(error_span!("dat:s"), {
                let store = store.clone();
                move |session| async move {
                    DataSender::new(session, store).run().await?;
                    Ok(())
                }
            });
        }

        // Spawn a task to handle incoming capabilities.
        self.spawn(error_span!("cap"), {
            let to_pai = to_pai_tx.clone();
            move |session| async move {
                while let Some(message) = capability_recv.try_next().await? {
                    let handle = message.handle;
                    session.on_setup_bind_read_capability(message)?;
                    to_pai
                        .send_async(ToPai::ReceivedReadCapForIntersection(handle))
                        .await
                        .map_err(|_| Error::InvalidState("PAI actor dead"))?;
                }
                Ok(())
            }
        });

        // Spawn a task to handle incoming areas of interest.
        self.spawn(error_span!("aoi"), move |session| async move {
            while let Some(message) = aoi_recv.try_next().await? {
                session.on_bind_area_of_interest(message).await?;
            }
            Ok(())
        });

        // Spawn a task to handle reconciliation messages
        self.spawn(error_span!("rec"), {
            let cancel_token = cancel_token.clone();
            let store = store.clone();
            move |session| async move {
                let res = Reconciler::new(session.clone(), store, reconciliation_recv)?
                    .run()
                    .await;
                if !session.mode().is_live() {
                    debug!("reconciliation complete and not in live mode: close session");
                    cancel_token.cancel();
                }
                res
            }
        });

        // Spawn a task to react to found PAI intersections.
        let pai_intersections = self.pai_intersection_stream();
        let mut pai_intersections = Cancelable::new(pai_intersections, cancel_token.clone());
        self.spawn(error_span!("pai:intersections"), {
            let store = store.clone();
            move |session| async move {
                while let Some(intersection) = pai_intersections.next().await {
                    session.on_pai_intersection(&store, intersection).await?;
                }
                Ok(())
            }
        });

        // Spawn a task to handle control messages
        self.spawn(error_span!("ctl"), {
            let cancel_token = cancel_token.clone();
            move |session| async move {
                let res = control_loop(session, control_recv, to_pai_tx).await;
                cancel_token.cancel();
                res
            }
        });

        // Wait until the session is cancelled, or until a task fails.
        let result = loop {
            tokio::select! {
                _ = cancel_token.cancelled() => {
                    break Ok(());
                },
                Some((span, result)) = self.join_next_task() => {
                    let _guard = span.enter();
                    trace!(?result, remaining = self.remaining_tasks(), "task complete");
                    if let Err(err) = result {
                        warn!(?err, "session task failed: abort session");
                        break Err(err);
                    }
                },
            }
        };

        if result.is_err() {
            self.abort_all_tasks();
        } else {
            debug!("closing session");
        }

        // Unsubscribe from the store.  This stops the data send task.
        store.entries().unsubscribe(self.id());

        // Wait for remaining tasks to terminate to catch any panics.
        // TODO: Add timeout?
        while let Some((span, result)) = self.join_next_task().await {
            let _guard = span.enter();
            trace!(?result, remaining = self.remaining_tasks(), "task complete");
            if let Err(err) = result {
                match err {
                    Error::TaskFailed(err) if err.is_cancelled() => {}
                    err => warn!("task failed: {err:?}"),
                }
            }
        }

        // Close our channel senders.
        // This will stop the network send loop after all pending data has been sent.
        self.close_senders();

        debug!(success = result.is_ok(), "session complete");
        result
    }
}

async fn control_loop(
    session: Session,
    mut control_recv: Cancelable<Receiver<Message>>,
    to_pai: flume::Sender<ToPai>,
) -> Result<(), Error> {
    debug!(role = ?session.our_role(), "start session");
    let mut commitment_revealed = false;

    // Reveal our nonce.
    let reveal_message = session.reveal_commitment()?;
    session.send(reveal_message).await?;

    // Issue guarantees for all logical channels.
    for channel in LogicalChannel::iter() {
        let msg = ControlIssueGuarantee {
            amount: INITIAL_GUARANTEES,
            channel,
        };
        session.send(msg).await?;
    }

    while let Some(message) = control_recv.try_next().await? {
        match message {
            Message::CommitmentReveal(msg) => {
                session.on_commitment_reveal(msg)?;
                if commitment_revealed {
                    return Err(Error::InvalidMessageInCurrentState)?;
                }
                commitment_revealed = true;
                let to_pai = to_pai.clone();
                session.spawn(error_span!("setup-pai"), move |session| {
                    setup_pai(session, to_pai)
                });
            }
            Message::ControlIssueGuarantee(msg) => {
                let ControlIssueGuarantee { amount, channel } = msg;
                // trace!(?channel, %amount, "add guarantees");
                session.add_guarantees(channel, amount);
            }
            Message::PaiRequestSubspaceCapability(msg) => {
                to_pai
                    .send_async(ToPai::ReceivedSubspaceCapRequest(msg.handle))
                    .await
                    .map_err(|_| Error::InvalidState("PAI actor dead"))?;
            }
            Message::PaiReplySubspaceCapability(msg) => {
                session.verify_subspace_capability(&msg)?;
                to_pai
                    .send_async(ToPai::ReceivedVerifiedSubspaceCapReply(
                        msg.handle,
                        msg.capability.granted_namespace().id(),
                    ))
                    .await
                    .map_err(|_| Error::InvalidState("PAI actor dead"))?;
            }
            _ => return Err(Error::UnsupportedMessage),
        }
    }

    Ok(())
}

async fn setup_pai(session: Session, to_pai: flume::Sender<ToPai>) -> Result<(), Error> {
    for authorisation in session.interests().keys() {
        to_pai
            .send_async(ToPai::SubmitAuthorisation(authorisation.clone()))
            .await
            .map_err(|_| Error::InvalidState("PAI actor dead"))?;
    }
    Ok(())
}
