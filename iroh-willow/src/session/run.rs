use std::{future::Future, sync::Arc};

use futures_concurrency::{
    future::{Join as _, TryJoin as _},
    stream::StreamExt as _,
};
use futures_lite::StreamExt as _;
use strum::IntoEnumIterator;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error_span, trace, Instrument, Span};

use crate::{
    net::ConnHandle,
    proto::wgps::{ControlIssueGuarantee, LogicalChannel, Message, SetupBindAreaOfInterest},
    session::{
        aoi_finder::{self, IntersectionFinder},
        capabilities::Capabilities,
        channels::{ChannelSenders, LogicalChannelReceivers},
        data,
        intents::{self, EventKind, Intent},
        pai_finder::{self as pai, PaiFinder},
        reconciler,
        static_tokens::StaticTokens,
        Channels, Error, EventSender, Role, SessionEvent, SessionId, SessionUpdate,
    },
    store::{traits::Storage, Store},
    util::{
        channel::Receiver,
        stream::{Cancelable, CancelableReceiver},
    },
};

use super::{
    channels::ChannelReceivers,
    data::{DataReceiver, DataSender},
    reconciler::Reconciler,
    SessionMode,
};

const INITIAL_GUARANTEES: u64 = u64::MAX;

pub(crate) async fn run_session<S: Storage>(
    store: Store<S>,
    conn: ConnHandle,
    initial_intents: Vec<Intent>,
    session_id: SessionId,
    event_sender: EventSender,
    update_receiver: ReceiverStream<SessionUpdate>,
) -> Result<(), Arc<Error>> {
    let ConnHandle {
        peer: _,
        initial_transmission,
        our_role,
        channels,
    } = conn;
    let Channels {
        send: channel_sender,
        recv,
    } = channels;
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

    // TODO: make mode change on intent changes
    let mode = initial_intents
        .iter()
        .fold(SessionMode::ReconcileOnce, |cur, intent| {
            match intent.init.mode {
                SessionMode::ReconcileOnce => cur,
                SessionMode::Continuous => SessionMode::Continuous,
            }
        });

    debug!(role = ?our_role, ?mode, "start session");

    // Make all our receivers close once the close session token is triggered.
    let close_session_token = CancellationToken::new();
    let control_recv = Cancelable::new(control_recv, close_session_token.clone());
    let reconciliation_recv = Cancelable::new(reconciliation_recv, close_session_token.clone());
    let intersection_recv = Cancelable::new(intersection_recv, close_session_token.clone());
    let mut static_tokens_recv = Cancelable::new(static_tokens_recv, close_session_token.clone());
    let mut capability_recv = Cancelable::new(capability_recv, close_session_token.clone());
    let mut aoi_recv = Cancelable::new(aoi_recv, close_session_token.clone());
    let mut data_recv = Cancelable::new(data_recv, close_session_token.clone());

    let caps = Capabilities::new(
        initial_transmission.our_nonce,
        initial_transmission.received_commitment,
    );
    let tokens = StaticTokens::default();

    // Setup channels for communication between the loops.
    // All channels but the intents channel are "cancelable", which means that once the cancel
    // token is invoked, no new messages may be sent into the channel.
    let close_inboxes_token = CancellationToken::new();
    let mut update_receiver = CancelableReceiver::new(update_receiver, close_inboxes_token.clone());
    let (pai_inbox, pai_inbox_rx) =
        cancelable_channel::<pai::Input>(2, close_inboxes_token.clone());
    let (intersection_inbox, intersection_inbox_rx) =
        cancelable_channel::<aoi_finder::Input>(2, close_inboxes_token.clone());
    let (reconciler_inbox, reconciler_inbox_rx) =
        cancelable_channel::<reconciler::Input>(2, close_inboxes_token.clone());

    // The closing ceremony for the intents inbox is more involved: It is a regular channel,
    // because the inbox should stay open after the cancel token is triggered, so that further
    // events may still be emitted. To close the channel, we manually ensure that all senders are
    // dropped once all other work is done.
    let (intents_inbox, intents_inbox_rx) = channel::<intents::Input>(2);

    // Setup data channels only if in live mode.
    // TODO: Adapt to changing mode.
    let (data_inbox, data_inbox_rx) = if mode == SessionMode::Continuous {
        let (data_inbox, data_inbox_rx) =
            cancelable_channel::<data::Input>(2, close_inboxes_token.clone());
        (Some(data_inbox), Some(data_inbox_rx))
    } else {
        (None, None)
    };

    let mut intents =
        intents::IntentDispatcher::new(store.auth().clone(), initial_intents, intents_inbox_rx);
    let intents_fut = with_span(error_span!("intents"), async {
        use intents::Output;
        let mut intents_gen = intents.run_gen();
        while let Some(output) = intents_gen.try_next().await? {
            trace!(?output, "yield");
            match output {
                Output::SubmitInterests(interests) => {
                    intersection_inbox
                        .send(aoi_finder::Input::AddInterests(interests))
                        .await
                        .ok();
                }
                // TODO: Add Output::SetMode(SessionMode) to propagate mode changes.
                Output::AllIntentsDropped => {
                    debug!("close session (all intents dropped)");
                    close_session_token.cancel();
                }
            }
        }
        Ok(())
    });

    let data_loop = with_span(error_span!("data"), async {
        // Start data loop only if in live mode.
        if let Some(inbox) = data_inbox_rx {
            let send_fut = DataSender::new(
                inbox,
                store.clone(),
                channel_sender.clone(),
                tokens.clone(),
                session_id,
            )
            .run();
            let recv_fut = async {
                let mut data_receiver =
                    DataReceiver::new(store.clone(), tokens.clone(), session_id);
                while let Some(message) = data_recv.try_next().await? {
                    data_receiver.on_message(message).await?;
                }
                trace!("data receiver terminated");
                Ok(())
            };
            (send_fut, recv_fut).try_join().await?;
            Ok(())
        } else {
            Ok(())
        }
    });

    let mut abort_err = None;

    let intents_inbox_2 = intents_inbox.clone();
    let update_loop = with_span(error_span!("update"), async {
        while let Some(update) = update_receiver.next().await {
            match update {
                SessionUpdate::SubmitIntent(data) => {
                    intents_inbox_2
                        .send(intents::Input::SubmitIntent(data))
                        .await?;
                }
                SessionUpdate::Abort(err) => {
                    abort_err = Some(err);
                    close_session_token.cancel();
                    break;
                }
            }
        }
        drop(intents_inbox_2);
        Ok(())
    });

    let intents_inbox_2 = intents_inbox.clone();
    let intersection_loop = with_span(error_span!("intersection"), async {
        use aoi_finder::Output;
        let mut gen = IntersectionFinder::run_gen(caps.clone(), intersection_inbox_rx);
        while let Some(output) = gen.try_next().await? {
            match output {
                Output::SendMessage(message) => channel_sender.send(message).await?,
                Output::SubmitAuthorisation(authorisation) => {
                    pai_inbox
                        .send(pai::Input::SubmitAuthorisation(authorisation))
                        .await
                        .ok();
                }
                Output::AoiIntersection(intersection) => {
                    let area = intersection.intersection.clone();
                    let namespace = intersection.namespace;
                    reconciler_inbox
                        .send(reconciler::Input::AoiIntersection(intersection.clone()))
                        .await
                        .ok();
                    let event = EventKind::InterestIntersection { namespace, area };
                    intents_inbox_2
                        .send(intents::Input::EmitEvent(event))
                        .await?;
                    if let Some(data_inbox) = &data_inbox {
                        data_inbox
                            .send(data::Input::AoiIntersection(intersection.clone()))
                            .await
                            .ok();
                    }
                }
                Output::SignAndSendCapability { handle, capability } => {
                    let message = caps.sign_capability(store.secrets(), handle, capability)?;
                    channel_sender.send(message).await?;
                }
            }
        }
        drop(intents_inbox_2);
        Ok(())
    });

    let intents_inbox_2 = intents_inbox.clone();
    let pai_loop = with_span(error_span!("pai"), async {
        use pai::Output;
        let inbox = pai_inbox_rx.merge(intersection_recv.map(pai::Input::ReceivedMessage));
        let mut gen = PaiFinder::run_gen(inbox);
        while let Some(output) = gen.try_next().await? {
            match output {
                Output::SendMessage(message) => channel_sender.send(message).await?,
                Output::NewIntersection(intersection) => {
                    let event = EventKind::CapabilityIntersection {
                        namespace: intersection.authorisation.namespace(),
                        area: intersection.authorisation.read_cap().granted_area().clone(),
                    };
                    let _ = (
                        intersection_inbox.send(aoi_finder::Input::PaiIntersection(intersection)),
                        intents_inbox_2.send(intents::Input::EmitEvent(event)),
                    )
                        .join()
                        .await;
                }
                Output::SignAndSendSubspaceCap(handle, cap) => {
                    let message = caps.sign_subspace_capability(store.secrets(), cap, handle)?;
                    channel_sender.send(Box::new(message)).await?;
                }
            }
        }
        drop(intents_inbox_2);
        Ok(())
    });

    let intents_inbox_2 = intents_inbox.clone();
    let reconciler_loop = with_span(error_span!("reconciler"), async {
        use reconciler::Output;
        let mut gen = Reconciler::run_gen(
            reconciler_inbox_rx,
            store.clone(),
            reconciliation_recv,
            tokens.clone(),
            session_id,
            channel_sender.clone(),
            our_role,
            initial_transmission.their_max_payload_size,
        );
        while let Some(output) = gen.try_next().await? {
            match output {
                Output::ReconciledArea { namespace, area } => {
                    intents_inbox_2
                        .send(intents::Input::EmitEvent(EventKind::Reconciled {
                            namespace,
                            area,
                        }))
                        .await?;
                }
                Output::ReconciledAll => {
                    // Stop session if not in live mode;
                    if !mode.is_live() {
                        debug!("close session (reconciliation finished and not in live mode)");
                        close_session_token.cancel();
                        break;
                    }
                }
            }
        }
        drop(intents_inbox_2);
        Ok(())
    });

    let token_recv_loop = with_span(error_span!("token_recv"), async {
        while let Some(message) = static_tokens_recv.try_next().await? {
            tokens.bind_theirs(message.static_token);
        }
        Ok(())
    });

    let caps_recv_loop = with_span(error_span!("caps_recv"), async {
        while let Some(message) = capability_recv.try_next().await? {
            let handle = message.handle;
            caps.validate_and_bind_theirs(message.capability.0, message.signature)?;
            pai_inbox
                .send(pai::Input::ReceivedReadCapForIntersection(handle))
                .await
                .ok();
        }
        Ok(())
    });

    let control_loop = with_span(error_span!("control"), async {
        let res = control_loop(
            control_recv,
            our_role,
            &caps,
            &channel_sender,
            &pai_inbox,
            &event_sender,
        )
        .await;
        // Once the control loop closed, close the inboxes.
        close_inboxes_token.cancel();
        res
    });

    let aoi_recv_loop = with_span(error_span!("aoi_recv"), async {
        while let Some(message) = aoi_recv.try_next().await? {
            let SetupBindAreaOfInterest {
                area_of_interest,
                authorisation,
            } = message;
            let area_of_interest = area_of_interest.0;
            let cap = caps.get_theirs_eventually(authorisation).await;
            if !cap.granted_area().includes_area(&area_of_interest.area) {
                return Err(Error::UnauthorisedArea);
            }
            let namespace = *cap.granted_namespace();
            intersection_inbox
                .send(aoi_finder::Input::ReceivedValidatedAoi {
                    namespace,
                    aoi: area_of_interest,
                })
                .await
                .ok();
        }
        Ok(())
    });

    // Drop the intents_inbox. We cloned this into the different loops, and the clones are dropped
    // at the end of the loops - which means the intents loop will terminate once all other loops
    // that potentially send into the intents inbox.
    drop(intents_inbox);

    let result = (
        intents_fut,
        control_loop,
        data_loop,
        update_loop,
        pai_loop,
        intersection_loop,
        reconciler_loop,
        token_recv_loop,
        caps_recv_loop,
        aoi_recv_loop,
    )
        .try_join()
        .await;

    // Unsubscribe from the store.
    store.entries().unsubscribe(&session_id);

    // Track if we closed the session by triggering the cancel token, or if the remote peer closed
    // the session by closing the control channel.
    let we_cancelled = close_session_token.is_cancelled();

    // Close the update receiver channel.
    let mut update_receiver = update_receiver.into_inner().into_inner();
    update_receiver.close();

    // Drain incomplete intents that are still in the intent dispatcher.
    let mut remaining_intents = intents.drain_all().await;

    // Drain the update receiver channel.
    while let Some(update) = update_receiver.recv().await {
        match update {
            SessionUpdate::SubmitIntent(intent) => remaining_intents.queued.push(intent),
            SessionUpdate::Abort(err) => {
                abort_err = Some(err);
            }
        }
    }

    let result = match (result, abort_err) {
        (_, Some(err)) => Err(Arc::new(err)),
        (Err(err), None) => Err(Arc::new(err)),
        _ => Ok(()),
    };

    let remaining_intents = match result.as_ref() {
        Err(err) => {
            remaining_intents.abort_all(err.clone()).await;
            vec![]
        }
        Ok(()) if we_cancelled => {
            drop(remaining_intents.active_incomplete);
            remaining_intents.queued
        }
        Ok(()) => {
            remaining_intents
                .abort_active(Arc::new(Error::SessionClosedByPeer))
                .await
        }
    };

    debug!(error=?result.as_ref().err(), remaining_intents=remaining_intents.len(), ?we_cancelled, "session complete");

    if let Err(_receiver_dropped) = event_sender
        .send(SessionEvent::Complete {
            result: result.clone(),
            we_cancelled,
            senders: channel_sender,
            remaining_intents,
        })
        .await
    {
        debug!("failed to send session complete event: receiver dropped");
    }

    result
}

async fn control_loop(
    mut control_recv: Cancelable<Receiver<Message>>,
    our_role: Role,
    caps: &Capabilities,
    sender: &ChannelSenders,
    pai_inbox: &mpsc::Sender<pai::Input>,
    event_sender: &EventSender,
) -> Result<(), Error> {
    // Reveal our nonce.
    let reveal_message = caps.reveal_commitment()?;
    sender.send(reveal_message).await?;

    // Issue guarantees for all logical channels.
    for channel in LogicalChannel::iter() {
        let msg = ControlIssueGuarantee {
            amount: INITIAL_GUARANTEES,
            channel,
        };
        sender.send(msg).await?;
    }

    // Handle incoming messages on the control channel.
    while let Some(message) = control_recv.try_next().await? {
        match message {
            Message::CommitmentReveal(msg) => {
                caps.received_commitment_reveal(our_role, msg.nonce)?;
                pai_inbox.send(pai::Input::Established).await?;
                event_sender.send(SessionEvent::Established).await?;
            }
            Message::ControlIssueGuarantee(msg) => {
                let ControlIssueGuarantee { amount, channel } = msg;
                // trace!(?channel, %amount, "add guarantees");
                sender.get_logical(channel).add_guarantees(amount);
            }
            Message::PaiRequestSubspaceCapability(msg) => {
                if !caps.is_revealed() {
                    return Err(Error::InvalidMessageInCurrentState);
                }
                pai_inbox
                    .send(pai::Input::ReceivedSubspaceCapRequest(msg.handle))
                    .await?;
            }
            Message::PaiReplySubspaceCapability(msg) => {
                if !caps.is_revealed() {
                    return Err(Error::InvalidMessageInCurrentState);
                }
                caps.verify_subspace_cap(&msg.capability, &msg.signature)?;
                pai_inbox
                    .send(pai::Input::ReceivedVerifiedSubspaceCapReply(
                        msg.handle,
                        *msg.capability.granted_namespace(),
                    ))
                    .await?;
            }
            _ => return Err(Error::UnsupportedMessage),
        }
    }
    trace!("control loop closing");

    Ok(())
}

fn channel<T: Send + 'static>(cap: usize) -> (mpsc::Sender<T>, mpsc::Receiver<T>) {
    let (tx, rx) = mpsc::channel(cap);
    (tx, rx)
}

fn cancelable_channel<T: Send + 'static>(
    cap: usize,
    cancel_token: CancellationToken,
) -> (mpsc::Sender<T>, CancelableReceiver<T>) {
    let (tx, rx) = mpsc::channel(cap);
    (
        tx,
        CancelableReceiver::new(ReceiverStream::new(rx), cancel_token),
    )
}

async fn with_span<T: std::fmt::Debug>(
    span: Span,
    fut: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    async {
        trace!("start");
        let res = fut.await;
        match &res {
            Ok(_) => trace!("done"),
            Err(err) => debug!(?err, "session task failed"),
        }
        res
    }
    .instrument(span)
    .await
}
