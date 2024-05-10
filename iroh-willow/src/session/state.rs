use std::{cell::RefCell, collections::HashSet, rc::Rc};

use tracing::warn;

use crate::proto::{
    challenge::ChallengeState,
    grouping::ThreeDRange,
    keys::{NamespaceId, UserSecretKey},
    wgps::{
        AccessChallenge, AreaOfInterestHandle, CapabilityHandle, ChallengeHash, CommitmentReveal,
        IntersectionHandle, Message, ReadCapability, SetupBindAreaOfInterest,
        SetupBindReadCapability, SetupBindStaticToken, StaticToken, StaticTokenHandle,
    },
};

use super::{resource::ScopedResources, Error, Role, Scope};
pub type SharedSessionState = Rc<RefCell<SessionState>>;

#[derive(Debug)]
pub struct SessionState {
    pub our_role: Role,
    pub our_resources: ScopedResources,
    pub their_resources: ScopedResources,
    pub reconciliation_started: bool,
    pub pending_ranges: HashSet<(AreaOfInterestHandle, ThreeDRange)>,
    pub pending_entries: Option<u64>,
    pub challenge: ChallengeState,
}

impl SessionState {
    pub fn new(
        our_role: Role,
        our_nonce: AccessChallenge,
        received_commitment: ChallengeHash,
        _their_maximum_payload_size: usize,
    ) -> Self {
        let challenge_state = ChallengeState::Committed {
            our_nonce,
            received_commitment,
        };
        Self {
            our_role,
            challenge: challenge_state,
            reconciliation_started: false,
            our_resources: Default::default(),
            their_resources: Default::default(),
            pending_ranges: Default::default(),
            pending_entries: Default::default(),
        }
    }
    fn resources(&self, scope: Scope) -> &ScopedResources {
        match scope {
            Scope::Ours => &self.our_resources,
            Scope::Theirs => &self.their_resources,
        }
    }
    pub fn reconciliation_is_complete(&self) -> bool {
        self.reconciliation_started
            && self.pending_ranges.is_empty()
            && self.pending_entries.is_none()
    }

    pub fn bind_and_sign_capability(
        &mut self,
        user_secret_key: &UserSecretKey,
        our_intersection_handle: IntersectionHandle,
        capability: ReadCapability,
    ) -> Result<(CapabilityHandle, Option<SetupBindReadCapability>), Error> {
        let signature = self.challenge.sign(user_secret_key)?;

        let (our_handle, is_new) = self
            .our_resources
            .capabilities
            .bind_if_new(capability.clone());
        let maybe_message = is_new.then(|| SetupBindReadCapability {
            capability,
            handle: our_intersection_handle,
            signature,
        });
        Ok((our_handle, maybe_message))
    }

    pub fn commitment_reveal(&mut self) -> Result<Message, Error> {
        match self.challenge {
            ChallengeState::Committed { our_nonce, .. } => {
                Ok(CommitmentReveal { nonce: our_nonce }.into())
            }
            _ => Err(Error::InvalidMessageInCurrentState),
        }
    }

    pub fn on_commitment_reveal(&mut self, msg: CommitmentReveal) -> Result<(), Error> {
        self.challenge.reveal(self.our_role, msg.nonce)
    }

    pub fn on_setup_bind_read_capability(
        &mut self,
        msg: SetupBindReadCapability,
    ) -> Result<(), Error> {
        // TODO: verify intersection handle
        msg.capability.validate()?;
        self.challenge
            .verify(msg.capability.receiver(), &msg.signature)?;
        self.their_resources.capabilities.bind(msg.capability);
        Ok(())
    }

    pub fn on_setup_bind_static_token(&mut self, msg: SetupBindStaticToken) {
        self.their_resources.static_tokens.bind(msg.static_token);
    }

    pub fn on_setup_bind_area_of_interest(
        &mut self,
        msg: SetupBindAreaOfInterest,
    ) -> Result<Option<(AreaOfInterestHandle, AreaOfInterestHandle)>, Error> {
        let capability = self
            .their_resources
            .capabilities
            .try_get(&msg.authorisation)?;
        capability.try_granted_area(&msg.area_of_interest.area)?;
        let their_handle = self.their_resources.areas_of_interest.bind(msg);

        // only initiate reconciliation if we are alfie, and if we have a shared aoi
        // TODO: abort if no shared aoi?
        let start = if self.our_role == Role::Alfie {
            self.find_shared_aoi(&their_handle)?
                .map(|our_handle| (our_handle, their_handle))
        } else {
            None
        };
        Ok(start)
    }

    pub fn find_shared_aoi(
        &self,
        their_handle: &AreaOfInterestHandle,
    ) -> Result<Option<AreaOfInterestHandle>, Error> {
        let their_aoi = self
            .their_resources
            .areas_of_interest
            .try_get(their_handle)?;
        let maybe_our_handle = self
            .our_resources
            .areas_of_interest
            .iter()
            .find(|(_handle, aoi)| aoi.area().intersection(their_aoi.area()).is_some())
            .map(|(handle, _aoi)| *handle);
        Ok(maybe_our_handle)
    }

    pub fn on_send_entry(&mut self) -> Result<(), Error> {
        let remaining = self
            .pending_entries
            .as_mut()
            .ok_or(Error::InvalidMessageInCurrentState)?;
        *remaining -= 1;
        if *remaining == 0 {
            self.pending_entries = None;
        }
        Ok(())
    }

    pub fn clear_pending_range_if_some(
        &mut self,
        our_handle: AreaOfInterestHandle,
        pending_range: Option<ThreeDRange>,
    ) -> Result<(), Error> {
        if let Some(range) = pending_range {
            // TODO: avoid clone
            if !self.pending_ranges.remove(&(our_handle, range.clone())) {
                warn!("received duplicate final reply for range marker");
                Err(Error::InvalidMessageInCurrentState)
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    pub fn bind_our_static_token(
        &mut self,
        static_token: StaticToken,
    ) -> anyhow::Result<(StaticTokenHandle, Option<SetupBindStaticToken>)> {
        let (handle, is_new) = self
            .our_resources
            .static_tokens
            .bind_if_new(static_token.clone());
        let msg = is_new.then(|| SetupBindStaticToken { static_token });
        Ok((handle, msg))
    }

    pub fn handle_to_namespace_id(
        &self,
        scope: Scope,
        handle: &AreaOfInterestHandle,
    ) -> Result<NamespaceId, Error> {
        let aoi = self.resources(scope).areas_of_interest.try_get(handle)?;
        let capability = self
            .resources(scope)
            .capabilities
            .try_get(&aoi.authorisation)?;
        let namespace_id = capability.granted_namespace().into();
        Ok(namespace_id)
    }

    pub fn range_is_authorised(
        &self,
        range: &ThreeDRange,
        receiver_handle: &AreaOfInterestHandle,
        sender_handle: &AreaOfInterestHandle,
    ) -> Result<NamespaceId, Error> {
        let our_namespace = self.handle_to_namespace_id(Scope::Ours, receiver_handle)?;
        let their_namespace = self.handle_to_namespace_id(Scope::Theirs, sender_handle)?;
        if our_namespace != their_namespace {
            return Err(Error::AreaOfInterestNamespaceMismatch);
        }
        let our_aoi = self.handle_to_aoi(Scope::Ours, receiver_handle)?;
        let their_aoi = self.handle_to_aoi(Scope::Theirs, sender_handle)?;

        if !our_aoi.area().includes_range(&range) || !their_aoi.area().includes_range(&range) {
            return Err(Error::RangeOutsideCapability);
        }
        Ok(our_namespace.into())
    }

    fn handle_to_aoi(
        &self,
        scope: Scope,
        handle: &AreaOfInterestHandle,
    ) -> Result<&SetupBindAreaOfInterest, Error> {
        self.resources(scope).areas_of_interest.try_get(handle)
    }
}
