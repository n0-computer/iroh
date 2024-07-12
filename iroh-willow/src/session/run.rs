use std::{cell::RefCell, collections::hash_map, rc::Rc};

use futures_concurrency::stream::StreamExt as _;
use futures_lite::StreamExt as _;
use genawaiter::GeneratorState;
use strum::IntoEnumIterator;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error_span, trace, warn, Span};

use crate::{
    auth::InterestMap,
    proto::sync::{ControlIssueGuarantee, InitialTransmission, LogicalChannel, Message},
    session::{
        aoi_finder::AoiFinder,
        capabilities::Capabilities,
        channels::{ChannelSenders, LogicalChannelReceivers},
        events::{EventKind, EventSender, SessionEvent},
        pai_finder::{self as pai, PaiFinder, PaiIntersection},
        static_tokens::StaticTokens,
        Channels, Error, Role, SessionId, SessionInit, SessionUpdate,
    },
    store::{
        traits::{SecretStorage, Storage},
        Store,
    },
    util::{channel::Receiver, stream::Cancelable, task::SharedJoinMap},
};

use super::{
    channels::ChannelReceivers,
    data::{DataReceiver, DataSender},
    reconciler::Reconciler,
    SessionMode,
};

const INITIAL_GUARANTEES: u64 = u64::MAX;

pub async fn run_session<S: Storage>(
    store: Store<S>,
    channels: Channels,
    cancel_token: CancellationToken,
    session_id: SessionId,
    our_role: Role,
    init: SessionInit,
    initial_transmission: InitialTransmission,
    event_sender: EventSender,
    update_receiver: flume::Receiver<SessionUpdate>,
) -> Result<(), Error> {
    debug!(role = ?our_role, mode = ?init.mode, "start session");
    let Channels { send, recv } = channels;
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
    let mut update_receiver = Cancelable::new(update_receiver.into_stream(), cancel_token.clone());

    let caps = Capabilities::new(
        initial_transmission.our_nonce,
        initial_transmission.received_commitment,
    );
    let tokens = StaticTokens::default();
    let aoi_finder = AoiFinder::default();

    let tasks = Tasks::default();

    let initial_interests = store.auth().resolve_interests(init.interests)?;
    let all_interests = Rc::new(RefCell::new(initial_interests.clone()));
    let initial_interests = Rc::new(initial_interests);

    // Setup a channel for the private area intersection finder.
    let (pai_inbox_tx, pai_inbox_rx) = flume::bounded(128);

    // Spawn a task to handle session updates.
    tasks.spawn(error_span!("upd"), {
        let store = store.clone();
        let caps = caps.clone();
        let to_pai = pai_inbox_tx.clone();
        let all_interests = all_interests.clone();
        let sender = send.clone();
        let aoi_finder = aoi_finder.clone();
        async move {
            while let Some(update) = update_receiver.next().await {
                match update {
                    SessionUpdate::AddInterests(interests) => {
                        caps.revealed().await;
                        let interests = store.auth().resolve_interests(interests)?;
                        for (authorisation, aois) in interests.into_iter() {
                            let mut all_interests = all_interests.borrow_mut();
                            let is_new_cap;
                            match all_interests.entry(authorisation.clone()) {
                                hash_map::Entry::Occupied(mut entry) => {
                                    is_new_cap = false;
                                    entry.get_mut().extend(aois.clone());
                                }
                                hash_map::Entry::Vacant(entry) => {
                                    is_new_cap = true;
                                    entry.insert(aois.clone());
                                }
                            }
                            drop(all_interests);
                            if let Some(capability_handle) =
                                caps.find_ours(authorisation.read_cap())
                            {
                                let namespace = authorisation.namespace();
                                for aoi in aois.into_iter() {
                                    aoi_finder
                                        .bind_and_send_ours(
                                            &sender,
                                            namespace,
                                            aoi,
                                            capability_handle,
                                        )
                                        .await?;
                                }
                            }
                            if is_new_cap {
                                to_pai
                                    .send_async(pai::Input::SubmitAuthorisation(authorisation))
                                    .await
                                    .map_err(|_| Error::InvalidState("PAI actor dead"))?;
                            }
                        }
                    }
                }
                // tokens.bind_theirs(message.static_token);
            }
            Ok(())
        }
    });

    // Spawn a task to setup the initial interests
    tasks.spawn(error_span!("setup-pai"), {
        let caps = caps.clone();
        let to_pai = pai_inbox_tx.clone();
        async move {
            caps.revealed().await;
            for authorisation in initial_interests.keys() {
                to_pai
                    .send_async(pai::Input::SubmitAuthorisation(authorisation.clone()))
                    .await
                    .map_err(|_| Error::InvalidState("PAI actor dead"))?;
            }
            Ok(())
        }
    });

    tasks.spawn(error_span!("pai"), {
        let store = store.clone();
        let send = send.clone();
        let caps = caps.clone();
        let inbox = pai_inbox_rx
            .into_stream()
            .merge(intersection_recv.map(pai::Input::ReceivedMessage));
        let interests = Rc::clone(&all_interests);
        let aoi_finder = aoi_finder.clone();
        let event_sender = event_sender.clone();
        async move {
            let mut gen = PaiFinder::run_gen(inbox);
            loop {
                match gen.async_resume().await {
                    GeneratorState::Yielded(output) => match output {
                        pai::Output::SendMessage(message) => send.send(message).await?,
                        pai::Output::NewIntersection(intersection) => {
                            let event = EventKind::CapabilityIntersection {
                                namespace: intersection.authorisation.namespace(),
                                area: intersection.authorisation.read_cap().granted_area().clone(),
                            };
                            event_sender.send(event).await?;
                            on_pai_intersection(
                                &interests,
                                store.secrets(),
                                &aoi_finder,
                                &caps,
                                &send,
                                intersection,
                            )
                            .await?;
                        }
                        pai::Output::SignAndSendSubspaceCap(handle, cap) => {
                            let message =
                                caps.sign_subspace_capabiltiy(store.secrets(), cap, handle)?;
                            send.send(Box::new(message)).await?;
                        }
                    },
                    GeneratorState::Complete(res) => {
                        return res;
                    }
                }
            }
        }
    });

    // Spawn a task to handle incoming static tokens.
    tasks.spawn(error_span!("stt"), {
        let tokens = tokens.clone();
        async move {
            while let Some(message) = static_tokens_recv.try_next().await? {
                tokens.bind_theirs(message.static_token);
            }
            Ok(())
        }
    });

    // Only setup data receiver if session is configured in live mode.
    if init.mode == SessionMode::Live {
        tasks.spawn(error_span!("data-recv"), {
            let store = store.clone();
            let tokens = tokens.clone();
            async move {
                let mut data_receiver = DataReceiver::new(store, tokens, session_id);
                while let Some(message) = data_recv.try_next().await? {
                    data_receiver.on_message(message).await?;
                }
                Ok(())
            }
        });
        tasks.spawn(error_span!("data-send"), {
            let store = store.clone();
            let tokens = tokens.clone();
            let send = send.clone();
            let aoi_intersections = aoi_finder.subscribe();
            async move {
                DataSender::new(store, send, aoi_intersections, tokens, session_id)
                    .run()
                    .await?;
                Ok(())
            }
        });
    }

    // Spawn a task to handle incoming capabilities.
    tasks.spawn(error_span!("cap-recv"), {
        let to_pai = pai_inbox_tx.clone();
        let caps = caps.clone();
        async move {
            while let Some(message) = capability_recv.try_next().await? {
                let handle = message.handle;
                caps.validate_and_bind_theirs(message.capability, message.signature)?;
                to_pai
                    .send_async(pai::Input::ReceivedReadCapForIntersection(handle))
                    .await
                    .map_err(|_| Error::InvalidState("PAI actor dead"))?;
            }
            Ok(())
        }
    });

    // Spawn a task to handle incoming areas of interest.
    tasks.spawn(error_span!("aoi-recv"), {
        let aoi_finder = aoi_finder.clone();
        let caps = caps.clone();
        async move {
            while let Some(message) = aoi_recv.try_next().await? {
                let cap = caps.get_theirs_eventually(message.authorisation).await;
                aoi_finder.validate_and_bind_theirs(&cap, message.area_of_interest)?;
            }
            aoi_finder.close();
            Ok(())
        }
    });

    // Spawn a task to handle reconciliation messages
    tasks.spawn(error_span!("rec"), {
        let cancel_token = cancel_token.clone();
        let aoi_intersections = aoi_finder.subscribe();
        let reconciler = Reconciler::new(
            store.clone(),
            reconciliation_recv,
            aoi_intersections,
            tokens.clone(),
            session_id,
            send.clone(),
            event_sender.clone(),
            our_role,
            init.mode,
        )?;
        async move {
            let res = reconciler.run().await;
            if res.is_ok() && !init.mode.is_live() {
                debug!("reconciliation complete and not in live mode: trigger cancel");
                cancel_token.cancel();
            }
            res
        }
    });

    // Spawn a task to handle control messages
    tasks.spawn(error_span!("ctl-recv"), {
        let cancel_token = cancel_token.clone();
        let fut = control_loop(our_role, caps, send.clone(), control_recv, pai_inbox_tx);
        async move {
            let res = fut.await;
            if res.is_ok() {
                debug!("control channel closed: trigger cancel");
                cancel_token.cancel();
            }
            res
        }
    });

    // Wait until the session is cancelled, or until a task fails.
    let result = loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                debug!("cancel token triggered: close session");
                break Ok(());
            },
            Some((span, result)) = tasks.join_next() => {
                let _guard = span.enter();
                trace!(?result, remaining = tasks.remaining_tasks(), "task complete");
                match result {
                    Err(err) => {
                        warn!(?err, "session task paniced: abort session");
                        break Err(Error::TaskFailed(err));
                    },
                    Ok(Err(err)) => {
                        warn!(?err, "session task failed: abort session");
                        break Err(err);
                    }
                    Ok(Ok(())) => {}
                }
            },
        }
    };

    if result.is_err() {
        debug!("aborting session");
        tasks.abort_all();
    } else {
        debug!("closing session");
    }

    // Unsubscribe from the store.  This stops the data send task.
    store.entries().unsubscribe(&session_id);

    // Wait for remaining tasks to terminate to catch any panics.
    // TODO: Add timeout?
    while let Some((span, result)) = tasks.join_next().await {
        let _guard = span.enter();
        trace!(
            ?result,
            remaining = tasks.remaining_tasks(),
            "task complete"
        );
        match result {
            Err(err) if err.is_cancelled() => {}
            Err(err) => warn!("task paniced: {err:?}"),
            Ok(Err(err)) => warn!("task failed: {err:?}"),
            Ok(Ok(())) => {}
        }
    }

    // Close our channel senders.
    // This will stop the network send loop after all pending data has been sent.
    send.close_all();

    debug!(success = result.is_ok(), "session complete");
    result
}

pub type Tasks = SharedJoinMap<Span, Result<(), Error>>;

async fn control_loop(
    our_role: Role,
    caps: Capabilities,
    sender: ChannelSenders,
    mut control_recv: Cancelable<Receiver<Message>>,
    to_pai: flume::Sender<pai::Input>,
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
            }
            Message::ControlIssueGuarantee(msg) => {
                let ControlIssueGuarantee { amount, channel } = msg;
                // trace!(?channel, %amount, "add guarantees");
                sender.get_logical(channel).add_guarantees(amount);
            }
            Message::PaiRequestSubspaceCapability(msg) => {
                to_pai
                    .send_async(pai::Input::ReceivedSubspaceCapRequest(msg.handle))
                    .await
                    .map_err(|_| Error::InvalidState("PAI actor dead"))?;
            }
            Message::PaiReplySubspaceCapability(msg) => {
                caps.verify_subspace_cap(&msg.capability, &msg.signature)?;
                to_pai
                    .send_async(pai::Input::ReceivedVerifiedSubspaceCapReply(
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

async fn on_pai_intersection<S: SecretStorage>(
    interests: &Rc<RefCell<InterestMap>>,
    secrets: &S,
    aoi_finder: &AoiFinder,
    capabilities: &Capabilities,
    sender: &ChannelSenders,
    intersection: PaiIntersection,
) -> Result<(), Error> {
    let PaiIntersection {
        authorisation,
        handle,
    } = intersection;
    let aois = {
        let interests = interests.borrow();
        interests
            .get(&authorisation)
            .ok_or(Error::NoKnownInterestsForCapability)?
            .clone()
    };
    let namespace = authorisation.namespace();
    let capability_handle = capabilities
        .bind_and_send_ours(secrets, sender, handle, authorisation.read_cap().clone())
        .await?;

    for aoi in aois.into_iter() {
        aoi_finder
            .bind_and_send_ours(sender, namespace, aoi, capability_handle)
            .await?;
    }
    Ok(())
}
