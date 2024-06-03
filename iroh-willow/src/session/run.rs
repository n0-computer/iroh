use futures_lite::StreamExt;
use strum::IntoEnumIterator;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error_span, trace};

use crate::{
    proto::sync::{ControlIssueGuarantee, LogicalChannel, Message, SetupBindAreaOfInterest},
    session::{channels::LogicalChannelReceivers, Error, Scope, Session, SessionInit},
    store::{traits::Storage, Store},
    util::channel::Receiver,
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
        finish: CancellationToken,
    ) -> Result<(), Error> {
        let ChannelReceivers {
            control_recv,
            logical_recv:
                LogicalChannelReceivers {
                    reconciliation_recv,
                    mut static_tokens_recv,
                    mut capability_recv,
                    mut aoi_recv,
                    data_recv,
                },
        } = recv;

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
                    DataReceiver::new(session, store, data_recv).run().await?;
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
            let finish = finish.clone();
            let store = store.clone();
            move |session| async move {
                let res = Reconciler::new(session, store, reconciliation_recv)?
                    .run()
                    .await;
                finish.cancel();
                res
            }
        });

        // Spawn a task to handle control messages
        self.spawn(error_span!("ctl"), {
            let finish = finish.clone();
            let store = store.clone();
            move |session| async move {
                let res = control_loop(session, store, control_recv, init).await;
                finish.cancel();
                res
            }
        });

        // Spawn a task to handle session termination.
        self.spawn(error_span!("fin"), move |session| async move {
            // Wait until the session is cancelled:
            // * either because SessionMode is ReconcileOnce and reconciliation finished
            // * or because the session was cancelled from the outside session handle
            finish.cancelled().await;
            // Then close all senders. This will make all other tasks terminate once the remote
            // closed their senders as well.
            session.close_senders();
            // Unsubscribe from the store.  This stops the data send task.
            store.entries().unsubscribe(session.id());
            Ok(())
        });

        // Wait for all tasks to complete.
        // We are not cancelling here so we have to make sure that all tasks terminate (structured
        // concurrency basically).
        let mut final_result = Ok(());
        while let Some((span, result)) = self.join_next_task().await {
            let _guard = span.enter();
            trace!(?result, remaining = self.remaining_tasks(), "task complete");
            if let Err(err) = result {
                tracing::warn!(?err, "task failed: {err}");
                if final_result.is_ok() {
                    final_result = Err(err);
                }
            }
        }
        debug!(success = final_result.is_ok(), "session complete");
        final_result
    }
}

async fn control_loop<S: Storage>(
    session: Session,
    store: Store<S>,
    mut control_recv: Receiver<Message>,
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
    debug!(interests = init.interests.len(), "start setup");
    for (capability, aois) in init.interests.into_iter() {
        // TODO: implement private area intersection
        let intersection_handle = 0.into();
        let (our_capability_handle, message) = session.bind_and_sign_capability(
            store.secrets(),
            intersection_handle,
            capability.clone(),
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
            session.bind_area_of_interest(Scope::Ours, msg.clone(), &capability)?;
            session.send(msg).await?;
        }
    }
    debug!("setup done");
    Ok(())
}
