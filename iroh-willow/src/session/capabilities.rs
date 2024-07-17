use std::{
    cell::RefCell,
    future::{poll_fn, Future},
    rc::Rc,
    task::{ready, Poll, Waker},
};

use tokio::sync::Notify;

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
    on_reveal_wakers: Vec<Waker>,
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
            on_reveal_wakers: Default::default(),
        })))
    }

    pub fn revealed(&self) -> impl Future<Output = ()> + '_ {
        std::future::poll_fn(|cx| {
            let mut inner = self.0.borrow_mut();
            if inner.challenge.is_revealed() {
                Poll::Ready(())
            } else {
                inner.on_reveal_wakers.push(cx.waker().to_owned());
                Poll::Pending
            }
        })
    }

    pub fn is_revealed(&self) -> bool {
        self.0.borrow().challenge.is_revealed()
    }

    pub fn find_ours(&self, cap: &ReadCapability) -> Option<CapabilityHandle> {
        self.0.borrow().ours.find(cap)
    }

    pub fn sign_capability<S: SecretStorage>(
        &self,
        secret_store: &S,
        intersection_handle: IntersectionHandle,
        capability: ReadCapability,
    ) -> Result<SetupBindReadCapability, Error> {
        let inner = self.0.borrow();
        let signable = inner.challenge.signable()?;
        let signature = secret_store.sign_user(&capability.receiver().id(), &signable)?;
        Ok(SetupBindReadCapability {
            capability,
            handle: intersection_handle,
            signature,
        })
    }

    pub fn bind_ours(&self, capability: ReadCapability) -> (CapabilityHandle, bool) {
        self.0.borrow_mut().ours.bind_if_new(capability)
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
        let mut inner = self.0.borrow_mut();
        inner.challenge.reveal(our_role, their_nonce)?;
        for waker in inner.on_reveal_wakers.drain(..) {
            waker.wake();
        }
        Ok(())
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
