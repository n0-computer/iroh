use std::{
    cell::RefCell,
    future::poll_fn,
    rc::Rc,
    task::{ready, Poll},
};

use crate::{
    proto::{
        challenge::ChallengeState,
        keys::UserSignature,
        sync::{
            AccessChallenge, CapabilityHandle, ChallengeHash, CommitmentReveal, IntersectionHandle,
            PaiReplySubspaceCapability, ReadCapability, SetupBindReadCapability,
            SubspaceCapability,
        },
    },
    session::{channels::ChannelSenders, resource::ResourceMap, Error, Role},
    store::traits::SecretStorage,
};

#[derive(Debug, Clone)]
pub struct Capabilities(Rc<RefCell<Inner>>);

#[derive(Debug)]
struct Inner {
    challenge: ChallengeState,
    ours: ResourceMap<CapabilityHandle, ReadCapability>,
    theirs: ResourceMap<CapabilityHandle, ReadCapability>,
}

impl Capabilities {
    pub fn new(our_nonce: AccessChallenge, received_commitment: ChallengeHash) -> Self {
        let challenge = ChallengeState::Committed {
            our_nonce,
            received_commitment,
        };
        Self(Rc::new(RefCell::new(Inner {
            challenge,
            ours: Default::default(),
            theirs: Default::default(),
        })))
    }

    pub async fn bind_and_send_ours<S: SecretStorage>(
        &self,
        secret_store: &S,
        sender: &ChannelSenders,
        intersection_handle: IntersectionHandle,
        capability: ReadCapability,
    ) -> Result<CapabilityHandle, Error> {
        let (handle, message) =
            self.bind_and_sign_ours(secret_store, intersection_handle, capability)?;
        if let Some(message) = message {
            sender.send(message).await?;
        }
        Ok(handle)
    }

    pub fn bind_and_sign_ours<S: SecretStorage>(
        &self,
        secret_store: &S,
        intersection_handle: IntersectionHandle,
        capability: ReadCapability,
    ) -> Result<(CapabilityHandle, Option<SetupBindReadCapability>), Error> {
        let mut inner = self.0.borrow_mut();
        let (handle, is_new) = inner.ours.bind_if_new(capability.clone());
        let message = if is_new {
            let signable = inner.challenge.signable()?;
            let signature = secret_store.sign_user(&capability.receiver().id(), &signable)?;
            Some(SetupBindReadCapability {
                capability,
                handle: intersection_handle,
                signature,
            })
        } else {
            None
        };
        Ok((handle, message))
    }

    pub fn validate_and_bind_theirs(
        &self,
        capability: ReadCapability,
        signature: UserSignature,
    ) -> Result<(), Error> {
        capability.validate()?;
        let mut inner = self.0.borrow_mut();
        inner.challenge.verify(capability.receiver(), &signature)?;
        inner.theirs.bind(capability);
        Ok(())
    }

    pub async fn get_theirs_eventually(&self, handle: CapabilityHandle) -> ReadCapability {
        poll_fn(|cx| {
            let mut inner = self.0.borrow_mut();
            let cap = ready!(inner.theirs.poll_get_eventually(handle, cx));
            Poll::Ready(cap.clone())
        })
        .await
    }

    pub fn verify_subspace_cap(
        &self,
        capability: &SubspaceCapability,
        signature: &UserSignature,
    ) -> Result<(), Error> {
        capability.validate()?;
        self.0
            .borrow_mut()
            .challenge
            .verify(capability.receiver(), signature)?;
        Ok(())
    }

    pub fn reveal_commitment(&self) -> Result<CommitmentReveal, Error> {
        match self.0.borrow_mut().challenge {
            ChallengeState::Committed { our_nonce, .. } => {
                Ok(CommitmentReveal { nonce: our_nonce })
            }
            _ => Err(Error::InvalidMessageInCurrentState),
        }
    }

    pub fn received_commitment_reveal(
        &self,
        our_role: Role,
        their_nonce: AccessChallenge,
    ) -> Result<(), Error> {
        self.0.borrow_mut().challenge.reveal(our_role, their_nonce)
    }

    pub fn sign_subspace_capabiltiy<S: SecretStorage>(
        &self,
        secrets: &S,
        cap: SubspaceCapability,
        handle: IntersectionHandle,
    ) -> Result<PaiReplySubspaceCapability, Error> {
        let inner = self.0.borrow();
        let signable = inner.challenge.signable()?;
        let signature = secrets.sign_user(&cap.receiver().id(), &signable)?;
        let message = PaiReplySubspaceCapability {
            handle,
            capability: cap.clone(),
            signature,
        };
        Ok(message)
    }
}
