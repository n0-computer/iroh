use futures_lite::StreamExt;
use strum::IntoEnumIterator;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error_span, trace, warn};

use crate::{
    proto::sync::{ControlIssueGuarantee, LogicalChannel, Message, SetupBindAreaOfInterest},
    session::{channels::LogicalChannelReceivers, Error, Scope, Session, SessionInit},
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
        init: SessionInit,
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
                },
        } = recv;

        // Make all our receivers close once the cancel_token is triggered.
        let control_recv = Cancelable::new(control_recv, cancel_token.clone());
        let reconciliation_recv = Cancelable::new(reconciliation_recv, cancel_token.clone());
        let mut static_tokens_recv = Cancelable::new(static_tokens_recv, cancel_token.clone());
        let mut capability_recv = Cancelable::new(capability_recv, cancel_token.clone());
        let mut aoi_recv = Cancelable::new(aoi_recv, cancel_token.clone());
        let mut data_recv = Cancelable::new(data_recv, cancel_token.clone());

        // Spawn a task to handle incoming static tokens.
        self.spawn(error_span!("stt"), move |session| async move {
            while let Some(message) = static_tokens_recv.try_next().await? {
                session.on_setup_bind_static_token(message);
            }
            Ok(())
        });

        // Only setup data receiver if session is configured in live mode.
        if init.mode == SessionMode::Live {
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
        self.spawn(error_span!("cap"), move |session| async move {
            while let Some(message) = capability_recv.try_next().await? {
                session.on_setup_bind_read_capability(message)?;
            }
            Ok(())
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

        // Spawn a task to handle control messages
        self.spawn(error_span!("ctl"), {
            let store = store.clone();
            let cancel_token = cancel_token.clone();
            move |session| async move {
                let res = control_loop(session, store, control_recv, init).await;
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
                warn!("task failed: {err:?}");
            }
        }

        // Close our channel senders.
        // This will stop the network send loop after all pending data has been sent.
        self.close_senders();

        debug!(success = result.is_ok(), "session complete");
        result
    }
}

async fn control_loop<S: Storage>(
    session: Session,
    store: Store<S>,
    mut control_recv: Cancelable<Receiver<Message>>,
    init: SessionInit,
) -> Result<(), Error> {
    debug!(role = ?session.our_role(), "start session");
    let mut init = Some(init);

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
                let init = init.take().ok_or(Error::InvalidMessageInCurrentState)?;
                // send setup messages, but in a separate task to not block incoming guarantees
                let store = store.clone();
                session.spawn(error_span!("setup"), move |session| {
                    setup(store, session, init)
                });
            }
            Message::ControlIssueGuarantee(msg) => {
                let ControlIssueGuarantee { amount, channel } = msg;
                trace!(?channel, %amount, "add guarantees");
                session.add_guarantees(channel, amount);
            }
            _ => return Err(Error::UnsupportedMessage),
        }
    }

    Ok(())
}

async fn setup<S: Storage>(
    store: Store<S>,
    session: Session,
    init: SessionInit,
) -> Result<(), Error> {
    // debug!(interests = init.interests.len(), "start setup");
    debug!(?init, "start setup");
    let interests = store.auth().find_read_caps_for_interests(init.interests)?;
    debug!(?interests, "found interests");
    for (authorisation, aois) in interests {
        // TODO: implement private area intersection
        let intersection_handle = 0.into();
        let read_cap = authorisation.read_cap();
        let (our_capability_handle, message) = session.bind_and_sign_capability(
            store.secrets(),
            intersection_handle,
            read_cap.clone(),
        )?;
        if let Some(message) = message {
            session.send(message).await?;
        }

        for area_of_interest in aois {
            let msg = SetupBindAreaOfInterest {
                area_of_interest,
                authorisation: our_capability_handle,
            };
            // TODO: We could skip the clone if we re-enabled sending by reference.
            session.bind_area_of_interest(Scope::Ours, msg.clone(), read_cap)?;
            session.send(msg).await?;
        }
    }
    debug!("setup done");
    Ok(())
}
