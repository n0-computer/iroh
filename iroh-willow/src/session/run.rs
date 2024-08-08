use std::{future::Future, sync::Arc};

use futures_concurrency::{future::TryJoin, stream::StreamExt as _};
use futures_lite::StreamExt as _;
use strum::IntoEnumIterator;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error_span, trace, warn, Instrument, Span};

use crate::{
    net::ConnHandle,
    proto::sync::{ControlIssueGuarantee, LogicalChannel, Message, SetupBindAreaOfInterest},
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
    util::{channel::Receiver, stream::Cancelable},
};

use super::{
    channels::ChannelReceivers,
    data::{DataReceiver, DataSender},
    error::ChannelReceiverDropped,
    reconciler::Reconciler,
    SessionMode,
};

const INITIAL_GUARANTEES: u64 = u64::MAX;

pub(crate) async fn run_session<S: Storage>(
    store: Store<S>,
    conn: ConnHandle,
    initial_intents: Vec<Intent>,
    cancel_token: CancellationToken,
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
                SessionMode::Live => SessionMode::Live,
            }
        });

    debug!(role = ?our_role, ?mode, "start session");

    // Make all our receivers close once the cancel_token is triggered.
    let control_recv = Cancelable::new(control_recv, cancel_token.clone());
    let reconciliation_recv = Cancelable::new(reconciliation_recv, cancel_token.clone());
    let intersection_recv = Cancelable::new(intersection_recv, cancel_token.clone());
    let mut static_tokens_recv = Cancelable::new(static_tokens_recv, cancel_token.clone());
    let mut capability_recv = Cancelable::new(capability_recv, cancel_token.clone());
    let mut aoi_recv = Cancelable::new(aoi_recv, cancel_token.clone());
    let mut data_recv = Cancelable::new(data_recv, cancel_token.clone());
    let mut update_receiver = Cancelable::new(update_receiver, cancel_token.clone());

    let caps = Capabilities::new(
        initial_transmission.our_nonce,
        initial_transmission.received_commitment,
    );
    let tokens = StaticTokens::default();

    // Setup channels for communication between the loops.
    let (pai_inbox, pai_inbox_rx) = cancelable_channel::<pai::Input>(2, cancel_token.clone());
    let (intersection_inbox, intersection_inbox_rx) =
        cancelable_channel::<aoi_finder::Input>(2, cancel_token.clone());
    let (reconciler_inbox, reconciler_inbox_rx) =
        cancelable_channel::<reconciler::Input>(2, cancel_token.clone());
    let (intents_inbox, intents_inbox_rx) =
        cancelable_channel::<intents::Input>(2, cancel_token.clone());

    // Setup data channels only if in live mode.
    // TODO: Adapt to changing mode.
    let (data_inbox, data_inbox_rx) = if mode == SessionMode::Live {
        let (data_inbox, data_inbox_rx) =
            cancelable_channel::<data::Input>(2, cancel_token.clone());
        (Some(data_inbox), Some(data_inbox_rx))
    } else {
        (None, None)
    };

    let mut intents = intents::IntentDispatcher::new(store.auth().clone(), initial_intents);
    let intents_fut = with_span(error_span!("intents"), async {
        use intents::Output;
        let mut intents_gen = intents.run_gen(intents_inbox_rx);
        while let Some(output) = intents_gen.try_next().await? {
            trace!(?output, "yield");
            match output {
                Output::SubmitInterests(interests) => {
                    intersection_inbox
                        .send(aoi_finder::Input::AddInterests(interests))
                        .await?;
                }
                // TODO: Add Output::SetMode(SessionMode) to propagate mode changes.
                Output::AllIntentsDropped => {
                    debug!("close session (all intents dropped)");
                    cancel_token.cancel();
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

    let update_loop = with_span(error_span!("update"), async {
        while let Some(update) = update_receiver.next().await {
            match update {
                SessionUpdate::SubmitIntent(data) => {
                    intents_inbox
                        .send(intents::Input::SubmitIntent(data))
                        .await?;
                }
            }
        }
        Ok(())
    });

    let intersection_loop = with_span(error_span!("intersection"), async {
        use aoi_finder::Output;
        let mut gen = IntersectionFinder::run_gen(caps.clone(), intersection_inbox_rx);
        while let Some(output) = gen.try_next().await? {
            match output {
                Output::SendMessage(message) => channel_sender.send(message).await?,
                Output::SubmitAuthorisation(authorisation) => {
                    pai_inbox
                        .send(pai::Input::SubmitAuthorisation(authorisation))
                        .await?;
                }
                Output::AoiIntersection(intersection) => {
                    let area = intersection.intersection.clone();
                    let namespace = intersection.namespace;
                    reconciler_inbox
                        .send(reconciler::Input::AoiIntersection(intersection.clone()))
                        .await?;
                    let event = EventKind::InterestIntersection { namespace, area };
                    intents_inbox.send(intents::Input::EmitEvent(event)).await?;
                    if let Some(data_inbox) = &data_inbox {
                        data_inbox
                            .send(data::Input::AoiIntersection(intersection.clone()))
                            .await?;
                    }
                }
                Output::SignAndSendCapability { handle, capability } => {
                    let message = caps.sign_capability(store.secrets(), handle, capability)?;
                    channel_sender.send(message).await?;
                }
            }
        }
        Ok(())
    });

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
                    (
                        intersection_inbox.send(aoi_finder::Input::PaiIntersection(intersection)),
                        intents_inbox.send(intents::Input::EmitEvent(event)),
                    )
                        .try_join()
                        .await?;
                }
                Output::SignAndSendSubspaceCap(handle, cap) => {
                    let message = caps.sign_subspace_capabiltiy(store.secrets(), cap, handle)?;
                    channel_sender.send(Box::new(message)).await?;
                }
            }
        }
        Ok(())
    });

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
        );
        while let Some(output) = gen.try_next().await? {
            match output {
                Output::ReconciledArea { namespace, area } => {
                    intents_inbox
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
                        cancel_token.cancel();
                        break;
                    }
                }
            }
        }
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
            caps.validate_and_bind_theirs(message.capability, message.signature)?;
            pai_inbox
                .send(pai::Input::ReceivedReadCapForIntersection(handle))
                .await?;
        }
        Ok(())
    });

    let mut we_cancelled = false;

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
        if !cancel_token.is_cancelled() {
            debug!("close session (closed by peer)");
            cancel_token.cancel();
        } else {
            we_cancelled = true;
        }
        res
    });

    let aoi_recv_loop = with_span(error_span!("aoi_recv"), async {
        while let Some(message) = aoi_recv.try_next().await? {
            let SetupBindAreaOfInterest {
                area_of_interest,
                authorisation,
            } = message;
            let cap = caps.get_theirs_eventually(authorisation).await;
            cap.try_granted_area(&area_of_interest.area)?;
            let namespace = cap.granted_namespace().id();
            intersection_inbox
                .send(aoi_finder::Input::ReceivedValidatedAoi {
                    namespace,
                    aoi: area_of_interest,
                })
                .await?;
        }
        Ok(())
    });

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

    let result = result.map_err(Arc::new).map(|_| ());

    debug!(error=?result.as_ref().err(), ?we_cancelled, "session complete");

    let remaining_intents = match result.as_ref() {
        Ok(()) => {
            // If the session closed without an error, return the remaining intents
            // so that they can potentially be restarted.
            intents.drain_all()
        }
        Err(err) => {
            // If the session closed with error, abort the intents with that error.
            intents.abort_all(err.clone()).await;
            vec![]
        }
    };

    if let Err(_receiver_dropped) = event_sender
        .send(SessionEvent::Complete {
            result: result.clone(),
            we_cancelled,
            senders: channel_sender,
            remaining_intents,
            update_receiver: update_receiver.into_inner().into_inner(),
        })
        .await
    {
        warn!("failed to send session complete event: receiver dropped");
    }

    result
}

async fn control_loop(
    mut control_recv: Cancelable<Receiver<Message>>,
    our_role: Role,
    caps: &Capabilities,
    sender: &ChannelSenders,
    pai_inbox: &Sender<pai::Input>,
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
                        msg.capability.granted_namespace().id(),
                    ))
                    .await?;
            }
            _ => return Err(Error::UnsupportedMessage),
        }
    }

    Ok(())
}

fn cancelable_channel<T: Send + 'static>(
    cap: usize,
    cancel_token: CancellationToken,
) -> (Sender<T>, Cancelable<ReceiverStream<T>>) {
    let (tx, rx) = mpsc::channel(cap);
    (
        Sender(tx),
        Cancelable::new(ReceiverStream::new(rx), cancel_token),
    )
}

#[derive(Debug)]
pub struct Sender<T>(mpsc::Sender<T>);

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Send> Sender<T> {
    async fn send(&self, item: T) -> Result<(), ChannelReceiverDropped> {
        self.0.send(item).await.map_err(|_| ChannelReceiverDropped)
    }
}

async fn with_span<T: std::fmt::Debug>(
    span: Span,
    fut: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    async {
        trace!("start");
        let res = fut.await;
        trace!(?res, "done");
        res
    }
    .instrument(span)
    .await
}
