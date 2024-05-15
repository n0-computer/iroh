use futures_lite::StreamExt;
use strum::IntoEnumIterator;
use tracing::{debug, error_span};

use crate::{
    proto::wgps::{ControlIssueGuarantee, LogicalChannel, Message, SetupBindAreaOfInterest},
    session::{channels::LogicalChannelReceivers, Error, Scope, Session, SessionInit},
    store::{KeyStore, Shared, Store},
    util::channel::Receiver,
};

use super::{channels::ChannelReceivers, reconciler::Reconciler};

const INITIAL_GUARANTEES: u64 = u64::MAX;

pub async fn run<S: Store, K: KeyStore>(
    store: Shared<S>,
    key_store: Shared<K>,
    session: Session,
    recv: ChannelReceivers,
    init: SessionInit,
) -> Result<(), Error> {
    let ChannelReceivers {
        control_recv,
        logical_recv,
    } = recv;
    let LogicalChannelReceivers {
        reconciliation_recv,
        mut static_tokens_recv,
        mut capability_recv,
        mut aoi_recv,
    } = logical_recv;

    // Spawn a task to handle incoming static tokens.
    session.spawn(error_span!("stt"), move |session| async move {
        while let Some(message) = static_tokens_recv.try_next().await? {
            session.on_setup_bind_static_token(message);
        }
        Ok(())
    });

    // Spawn a task to handle incoming capabilities.
    session.spawn(error_span!("cap"), move |session| async move {
        while let Some(message) = capability_recv.try_next().await? {
            session.on_setup_bind_read_capability(message)?;
        }
        Ok(())
    });

    // Spawn a task to handle incoming areas of interest.
    session.spawn(error_span!("aoi"), move |session| async move {
        while let Some(message) = aoi_recv.try_next().await? {
            session.on_bind_area_of_interest(message).await?;
        }
        Ok(())
    });

    // Spawn a task to handle reconciliation messages
    session.spawn(error_span!("rec"), move |session| async move {
        Reconciler::new(session, store, reconciliation_recv)?.run().await
    });

    // Spawn a task to handle control messages
    session.spawn(tracing::Span::current(), move |session| async move {
        control_loop(session, key_store, control_recv, init).await
    });

    // Loop over task completions, break on failure or if reconciliation completed
    while let Some((span, result)) = session.join_next_task().await {
        let guard = span.enter();
        debug!(?result, "task completed");
        result?;
        // Is this the right place for this check? It would run after each task
        // completion, so necessarily including the completion of the reconciliation
        // task, which is the only condition in which reconciliation can complete at
        // the moment.
        //
        // TODO: We'll want to emit the completion event back to the application and
        // let it decide what to do (stop, keep open) - or pass relevant config in
        // SessionInit.
        if session.reconciliation_is_complete() {
            tracing::debug!("stop session: reconciliation is complete");
            drop(guard);
            break;
        }
    }

    // Close all our send streams.
    //
    // This makes the networking send loops stop.
    session.close_senders();

    Ok(())
}

async fn control_loop<K: KeyStore>(
    session: Session,
    key_store: Shared<K>,
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
        debug!(%message, "recv");
        match message {
            Message::CommitmentReveal(msg) => {
                session.on_commitment_reveal(msg)?;
                let init = init.take().ok_or(Error::InvalidMessageInCurrentState)?;
                // send setup messages, but in a separate task to not block incoming guarantees
                let key_store = key_store.clone();
                session.spawn(error_span!("setup"), |session| setup(key_store, session, init));
            }
            Message::ControlIssueGuarantee(msg) => {
                let ControlIssueGuarantee { amount, channel } = msg;
                debug!(?channel, %amount, "add guarantees");
                session.add_guarantees(channel, amount);
            }
            _ => return Err(Error::UnsupportedMessage),
        }
    }

    Ok(())
}

async fn setup<K: KeyStore>(key_store: Shared<K>, session: Session, init: SessionInit) -> Result<(), Error> {
    debug!(interests = init.interests.len(), "start setup");
    for (capability, aois) in init.interests.into_iter() {
        // TODO: implement private area intersection
        let intersection_handle = 0.into();
        let (our_capability_handle, message) =
            session.bind_and_sign_capability(&key_store, intersection_handle, capability)?;
        if let Some(message) = message {
            session.send(message).await?;
        }

        for area_of_interest in aois {
            let msg = SetupBindAreaOfInterest {
                area_of_interest,
                authorisation: our_capability_handle,
            };
            // TODO: We could skip the clone if we re-enabled sending by reference.
            session.bind_area_of_interest(Scope::Ours, msg.clone())?;
            session.send(msg).await?;
        }
    }
    debug!("setup done");
    Ok(())
}
