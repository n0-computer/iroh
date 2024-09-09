use std::{
    cell::RefCell,
    future::poll_fn,
    rc::Rc,
    task::{ready, Poll, Waker},
};

use crate::{
    proto::{
        keys::UserSignature,
        meadowcap::{ReadCapability, SubspaceCapability},
        wgps::{
            AccessChallenge, CapabilityHandle, ChallengeHash, CommitmentReveal, IntersectionHandle,
            PaiReplySubspaceCapability, SetupBindReadCapability,
        },
    },
    session::{challenge::ChallengeState, resource::ResourceMap, Error, Role},
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

    // pub fn revealed(&self) -> impl Future<Output = ()> + '_ {
    //     std::future::poll_fn(|cx| {
    //         let mut inner = self.0.borrow_mut();
    //         if inner.challenge.is_revealed() {
    //             Poll::Ready(())
    //         } else {
    //             inner.on_reveal_wakers.push(cx.waker().to_owned());
    //             Poll::Pending
    //         }
    //     })
    // }

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
        let signature = secret_store.sign_user(capability.receiver(), &signable)?;
        Ok(SetupBindReadCapability {
            capability: capability.into(),
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
        // TODO(Frando): I *think* meadowcap caps are always validated (no way to construct invalid ones).
        // capability.validate()?;
        let mut inner = self.0.borrow_mut();
        // TODO(Frando): We should somehow remove the `Id`/`PublicKey` split.
        let receiver_key = capability.receiver().into_public_key()?;
        inner.challenge.verify(&receiver_key, &signature)?;
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
        // TODO(Frando): I *think* meadowcap caps are always validated (no way to construct invalid ones).
        // capability.validate()?;
        // TODO(Frando): We should somehow remove the `Id`/`PublicKey` split.
        let receiver_key = capability.receiver().into_public_key()?;
        self.0
            .borrow_mut()
            .challenge
            .verify(&receiver_key, signature)?;
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

    pub fn sign_subspace_capability<S: SecretStorage>(
        &self,
        secrets: &S,
        cap: SubspaceCapability,
        handle: IntersectionHandle,
    ) -> Result<PaiReplySubspaceCapability, Error> {
        let inner = self.0.borrow();
        let signable = inner.challenge.signable()?;
        let signature = secrets.sign_user(cap.receiver(), &signable)?;
        let message = PaiReplySubspaceCapability {
            handle,
            capability: cap.clone().into(),
            signature,
        };
        Ok(message)
    }
}
