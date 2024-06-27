//! Private Area Intersection finder
//!
//! As defined by the willow spec: [Private Area Intersection](https://willowprotocol.org/specs/pai/index.html)
//!
//! Partly ported from the implementation in earthstar and willow:
//! * https://github.com/earthstar-project/willow-js/blob/0db4b9ec7710fb992ab75a17bd8557040d9a1062/src/wgps/pai/pai_finder.ts
//! * https://github.com/earthstar-project/earthstar/blob/16d6d4028c22fdbb72f7395013b29be7dcd9217a/src/schemes/schemes.ts#L662
//! Licensed under LGPL and ported into this MIT/Apache codebase with explicit permission
//! from the original author (gwil).

use std::collections::{HashMap, HashSet};

use anyhow::Result;
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use futures_lite::StreamExt;
use tracing::debug;

use crate::{
    proto::{
        grouping::SubspaceArea,
        sync::{
            IntersectionHandle, IntersectionMessage, PaiBindFragment, PaiReplyFragment,
            PaiRequestSubspaceCapability, ReadAuthorisation, ReadCapability,
        },
        willow::{NamespaceId, Path, SubspaceId},
    },
    session::{
        channels::MessageReceiver,
        resource::{MissingResource, ResourceMap},
        Error, Scope, Session,
    },
    store::{traits::Storage, Store},
    util::{codec::Encoder, stream::Cancelable},
};

#[derive(Debug, thiserror::Error)]
pub enum PaiError {
    #[error("Partner replied with subspace cap for handle which we never sent a request for")]
    SubspaceCapRequestForInvalidHandle,
    #[error("Partner replied with subspace capability for the wrong namespace")]
    SubspaceCapRequestForWrongNamespace,
    #[error("Missing resource {:?}", _0.0)]
    MissingResource(#[from] MissingResource),
}

#[derive(Debug)]
pub enum ToPai {
    SubmitAuthorisation(ReadAuthorisation),
    ReceivedSubspaceCapRequest(IntersectionHandle),
    ReceivedVerifiedSubspaceCapReply(IntersectionHandle, NamespaceId),
    ReceivedReadCapForIntersection(IntersectionHandle),
}

#[derive(Debug)]
pub struct PaiFinder<S: Storage> {
    session: Session,
    store: Store<S>,
    scalar: PsiScalar,
    fragments_info: HashMap<IntersectionHandle, LocalFragmentInfo>,
    our_intersection_handles: ResourceMap<IntersectionHandle, FragmentInfo>,
    their_intersection_handles: ResourceMap<IntersectionHandle, FragmentInfo>,
    requested_subspace_cap_handles: HashSet<IntersectionHandle>,
}

impl<S: Storage> PaiFinder<S> {
    pub fn new(session: Session, store: Store<S>) -> Self {
        Self {
            session,
            store,
            scalar: PaiScheme::get_scalar(),
            our_intersection_handles: Default::default(),
            their_intersection_handles: Default::default(),
            fragments_info: Default::default(),
            requested_subspace_cap_handles: Default::default(),
        }
    }

    pub async fn run(
        mut self,
        to_pai: flume::Receiver<ToPai>,
        mut recv: Cancelable<MessageReceiver<IntersectionMessage>>,
    ) -> Result<(), Error> {
        loop {
            tokio::select! {
                action = to_pai.recv_async() => {
                    match action {
                        Err(_) => break,
                        Ok(action) => self.on_action(action).await?
                    }
                }
                message = recv.next() => {
                    match message {
                        None => break,
                        Some(message) => self.on_message(message?).await?
                    }
                }
            }
        }
        Ok(())
    }

    async fn on_message(&mut self, message: IntersectionMessage) -> Result<(), Error> {
        debug!("on_message {message:?}");
        match message {
            IntersectionMessage::BindFragment(message) => self.receive_bind(message).await?,
            IntersectionMessage::ReplyFragment(message) => self.receive_reply(message).await?,
        }
        Ok(())
    }

    async fn on_action(&mut self, action: ToPai) -> Result<(), Error> {
        debug!("on_action {action:?}");
        match action {
            ToPai::SubmitAuthorisation(auth) => self.submit_autorisation(auth).await?,
            ToPai::ReceivedSubspaceCapRequest(handle) => {
                self.received_subspace_cap_request(handle).await?
            }
            ToPai::ReceivedVerifiedSubspaceCapReply(handle, namespace) => {
                self.received_verified_subspace_cap_reply(handle, namespace)?
            }
            ToPai::ReceivedReadCapForIntersection(handle) => {
                self.received_read_cap_for_intersection(handle)?
            }
        }
        Ok(())
    }

    async fn submit_autorisation(&mut self, authorisation: ReadAuthorisation) -> Result<(), Error> {
        let read_cap = authorisation.read_cap();
        let fragment_kit = PaiScheme::get_fragment_kit(read_cap);
        let fragment_set = fragment_kit.into_fragment_set();
        match fragment_set {
            FragmentSet::Complete(pairs) => {
                let last = pairs.len().wrapping_sub(1);
                for (i, pair) in pairs.into_iter().enumerate() {
                    let is_most_specific = i == last;
                    let (namespace_id, path) = pair.clone();
                    let (handle, message) = self.submit_fragment(Fragment::Pair(pair), false)?;
                    let info = LocalFragmentInfo {
                        on_intersection: IntersectionAction::new_primary(is_most_specific),
                        authorisation: authorisation.clone(),
                        namespace_id,
                        path,
                        subspace: SubspaceArea::Any,
                    };
                    self.fragments_info.insert(handle, info);
                    self.session.send(message).await?;
                }
            }
            FragmentSet::Selective { primary, secondary } => {
                let last = primary.len().wrapping_sub(1);
                for (i, triple) in primary.into_iter().enumerate() {
                    let is_most_specific = i == last;
                    let (namespace_id, subspace_id, path) = triple.clone();
                    let (handle, message) =
                        self.submit_fragment(Fragment::Triple(triple), false)?;
                    let info = LocalFragmentInfo {
                        on_intersection: IntersectionAction::new_primary(is_most_specific),
                        authorisation: authorisation.clone(),
                        namespace_id,
                        path,
                        subspace: SubspaceArea::Id(subspace_id),
                    };
                    self.fragments_info.insert(handle, info);
                    self.session.send(message).await?;
                }
                let last = secondary.len().wrapping_sub(1);
                for (i, pair) in secondary.into_iter().enumerate() {
                    let is_most_specific = i == last;
                    let (namespace_id, path) = pair.clone();
                    let (handle, message) = self.submit_fragment(Fragment::Pair(pair), true)?;
                    let info = LocalFragmentInfo {
                        on_intersection: IntersectionAction::new_secondary(is_most_specific),
                        authorisation: authorisation.clone(),
                        namespace_id,
                        path,
                        subspace: SubspaceArea::Any,
                    };
                    self.fragments_info.insert(handle, info);
                    self.session.send(message).await?;
                }
            }
        }
        Ok(())
    }

    fn submit_fragment(
        &mut self,
        fragment: Fragment,
        is_secondary: bool,
    ) -> Result<(IntersectionHandle, PaiBindFragment)> {
        let unmixed = PaiScheme::fragment_to_group(fragment);
        let multiplied = PaiScheme::scalar_mult(unmixed, self.scalar);
        let info = FragmentInfo {
            group: multiplied,
            state: FragmentState::Pending,
            is_secondary,
        };
        let message = info.to_message();
        let handle = self.our_intersection_handles.bind(info);
        Ok((handle, message))
    }

    async fn receive_bind(&mut self, message: PaiBindFragment) -> Result<()> {
        let PaiBindFragment {
            group_member,
            is_secondary,
        } = message;
        let unmixed = PsiGroup::from_bytes(group_member)?;
        let multiplied = PaiScheme::scalar_mult(unmixed, self.scalar);
        let fragment = FragmentInfo {
            group: multiplied,
            is_secondary,
            state: FragmentState::Pending,
        };
        let handle = self.their_intersection_handles.bind(fragment);
        let reply = PaiReplyFragment {
            handle,
            group_member,
        };
        self.session.send(reply).await?;
        self.check_for_intersection(handle, Scope::Theirs).await?;
        Ok(())
    }

    async fn receive_reply(&mut self, message: PaiReplyFragment) -> Result<()> {
        let PaiReplyFragment {
            handle,
            group_member,
        } = message;
        let group_member = PsiGroup::from_bytes(group_member)?;
        let intersection = self.our_intersection_handles.try_get(&handle)?;
        let fragment = FragmentInfo {
            group: group_member,
            is_secondary: intersection.is_secondary,
            state: FragmentState::Complete,
        };
        self.our_intersection_handles.update(handle, fragment)?;
        self.check_for_intersection(handle, Scope::Ours).await?;
        Ok(())
    }

    async fn check_for_intersection(
        &mut self,
        handle: IntersectionHandle,
        scope: Scope,
    ) -> Result<(), Error> {
        let store_to_check = match scope {
            Scope::Ours => &self.our_intersection_handles,
            Scope::Theirs => &self.their_intersection_handles,
        };
        let intersection = store_to_check.try_get(&handle)?;

        if !intersection.is_complete() {
            return Ok(());
        }

        // Here we are looping through the whole contents of the handle store because...
        // otherwise we need to build a special handle store just for intersections.
        // Which we might do one day, but I'm not convinced it's worth it yet.
        for (other_handle, other_intersection) in store_to_check.iter() {
            if !other_intersection.completes_with(intersection) {
                continue;
            }

            // If there is an intersection, check what we have to do!
            let our_handle = match scope {
                Scope::Ours => handle,
                Scope::Theirs => *other_handle,
            };

            let fragment_info = self
                .fragments_info
                .get(&our_handle)
                .ok_or(Error::MissingResource(our_handle.into()))?;

            match fragment_info.on_intersection {
                IntersectionAction::BindReadCap => {
                    let intersection = fragment_info.to_pai_intersection(our_handle);
                    self.session.push_pai_intersection(intersection);
                }
                IntersectionAction::RequestSubspaceCap => {
                    self.requested_subspace_cap_handles.insert(our_handle);
                    let message = PaiRequestSubspaceCapability { handle };
                    self.session.send(message).await?;
                }
                IntersectionAction::ReplyReadCap | IntersectionAction::DoNothing => {}
            }
        }

        Ok(())
    }

    fn received_read_cap_for_intersection(
        &mut self,
        their_handle: IntersectionHandle,
    ) -> Result<()> {
        let their_intersection = self.their_intersection_handles.try_get(&their_handle)?;
        for (our_handle, our_intersection) in self.our_intersection_handles.iter() {
            if !our_intersection.completes_with(their_intersection) {
                continue;
            }
            let fragment_info = self
                .fragments_info
                .get(our_handle)
                .ok_or(Error::MissingResource((*our_handle).into()))?;
            if let IntersectionAction::ReplyReadCap = fragment_info.on_intersection {
                let intersection = fragment_info.to_pai_intersection(*our_handle);
                self.session.push_pai_intersection(intersection);
            }
        }
        Ok(())
    }

    fn received_verified_subspace_cap_reply(
        &mut self,
        handle: IntersectionHandle,
        namespace_id: NamespaceId,
    ) -> Result<(), PaiError> {
        if !self.requested_subspace_cap_handles.remove(&handle) {
            return Err(PaiError::SubspaceCapRequestForInvalidHandle);
        }
        let _ = self.our_intersection_handles.try_get(&handle)?;
        let fragment_info = self
            .fragments_info
            .get(&handle)
            .ok_or(PaiError::SubspaceCapRequestForInvalidHandle)?;

        if fragment_info.namespace_id != namespace_id {
            return Err(PaiError::SubspaceCapRequestForWrongNamespace);
        }
        let intersection = fragment_info.to_pai_intersection(handle);
        self.session.push_pai_intersection(intersection);
        Ok(())
    }

    pub async fn received_subspace_cap_request(
        &mut self,
        handle: IntersectionHandle,
    ) -> Result<(), Error> {
        let result = self.their_intersection_handles.try_get(&handle)?;
        for (our_handle, intersection) in self.our_intersection_handles.iter() {
            if !intersection.is_complete() {
                continue;
            }
            if !PaiScheme::is_group_equal(&result.group, &intersection.group) {
                continue;
            }
            let fragment_info = self
                .fragments_info
                .get(our_handle)
                .ok_or(PaiError::SubspaceCapRequestForInvalidHandle)?;
            if let Some(cap) = fragment_info.authorisation.subspace_cap() {
                let message =
                    self.session
                        .sign_subspace_capabiltiy(self.store.secrets(), cap, handle)?;
                self.session.send(Box::new(message)).await?;
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct LocalFragmentInfo {
    on_intersection: IntersectionAction,
    authorisation: ReadAuthorisation,
    namespace_id: NamespaceId,
    // will be needed for spec-compliant encodings of read capabilities
    #[allow(dead_code)]
    path: Path,
    // will be needed for spec-compliant encodings of read capabilities
    #[allow(dead_code)]
    subspace: SubspaceArea,
}

impl LocalFragmentInfo {
    fn to_pai_intersection(&self, handle: IntersectionHandle) -> PaiIntersection {
        PaiIntersection {
            authorisation: self.authorisation.clone(),
            handle,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Fragment {
    Pair(FragmentPair),
    Triple(FragmentTriple),
}

impl Encoder for Fragment {
    fn encoded_len(&self) -> usize {
        match self {
            Fragment::Pair((_, path)) => NamespaceId::LENGTH + path.encoded_len(),
            Fragment::Triple((_, _, path)) => {
                NamespaceId::LENGTH + SubspaceId::LENGTH + path.encoded_len()
            }
        }
    }
    fn encode_into<W: std::io::Write>(&self, out: &mut W) -> Result<()> {
        match self {
            Fragment::Pair((namespace_id, path)) => {
                out.write_all(namespace_id.as_bytes())?;
                path.encode_into(out)?;
            }
            Fragment::Triple((namespace_id, subspace_id, path)) => {
                out.write_all(namespace_id.as_bytes())?;
                out.write_all(subspace_id.as_bytes())?;
                path.encode_into(out)?;
            }
        }
        Ok(())
    }
}

pub type FragmentTriple = (NamespaceId, SubspaceId, Path);

pub type FragmentPair = (NamespaceId, Path);

#[derive(Debug, Clone)]
pub enum FragmentSet {
    Complete(Vec<FragmentPair>),
    Selective {
        primary: Vec<FragmentTriple>,
        secondary: Vec<FragmentPair>,
    },
}

#[derive(Debug)]
pub enum FragmentKit {
    Complete(NamespaceId, Path),
    Selective(NamespaceId, SubspaceId, Path),
}

impl FragmentKit {
    fn into_fragment_set(self) -> FragmentSet {
        match self {
            FragmentKit::Complete(namespace_id, path) => {
                let mut pairs = vec![];
                for prefix in prefixes_of(&path) {
                    pairs.push((namespace_id, prefix));
                }
                FragmentSet::Complete(pairs)
            }
            FragmentKit::Selective(namespace_id, subspace_id, path) => {
                let mut primary = vec![];
                let mut secondary = vec![];
                for prefix in prefixes_of(&path) {
                    primary.push((namespace_id, subspace_id, prefix.clone()));
                    secondary.push((namespace_id, prefix.clone()));
                }
                FragmentSet::Selective { primary, secondary }
            }
        }
    }
}

fn prefixes_of(path: &Path) -> Vec<Path> {
    let mut out = vec![Path::empty()];
    let components = path.components();
    if components.is_empty() {
        return out;
    }
    for i in 1..=components.len() {
        let prefix = Path::from_components(&components[..i]);
        out.push(prefix);
    }
    out
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PsiGroup(RistrettoPoint);

#[derive(Debug, thiserror::Error)]
#[error("Invalid Psi Group")]
pub struct InvalidPsiGroup;

impl PsiGroup {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, InvalidPsiGroup> {
        let compressed = CompressedRistretto(bytes);
        let uncompressed = compressed.decompress().ok_or(InvalidPsiGroup)?;
        Ok(Self(uncompressed))
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0.compress().0
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PsiScalar(Scalar);

pub struct PaiScheme;

impl PaiScheme {
    fn fragment_to_group(fragment: Fragment) -> PsiGroup {
        let encoded = fragment.encode().expect("encoding not to fail");
        let point = RistrettoPoint::hash_from_bytes::<sha2::Sha512>(&encoded);
        PsiGroup(point)
    }

    fn get_scalar() -> PsiScalar {
        PsiScalar(Scalar::random(&mut rand::thread_rng()))
    }

    fn scalar_mult(group: PsiGroup, scalar: PsiScalar) -> PsiGroup {
        PsiGroup(group.0 * scalar.0)
    }

    fn is_group_equal(a: &PsiGroup, b: &PsiGroup) -> bool {
        a == b
    }

    fn get_fragment_kit(cap: &ReadCapability) -> FragmentKit {
        let granted_area = cap.granted_area();
        let granted_namespace = cap.granted_namespace().id();
        let granted_path = granted_area.path.clone();

        match granted_area.subspace {
            SubspaceArea::Any => FragmentKit::Complete(granted_namespace, granted_path),
            SubspaceArea::Id(granted_subspace) => {
                FragmentKit::Selective(granted_namespace, granted_subspace, granted_path)
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum FragmentState {
    Pending,
    Complete,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FragmentInfo {
    group: PsiGroup,
    state: FragmentState,
    is_secondary: bool,
}

#[derive(Debug)]
pub struct PaiIntersection {
    pub authorisation: ReadAuthorisation,
    pub handle: IntersectionHandle,
}

impl FragmentInfo {
    fn to_message(&self) -> PaiBindFragment {
        PaiBindFragment {
            group_member: self.group.to_bytes(),
            is_secondary: self.is_secondary,
        }
    }

    fn is_complete(&self) -> bool {
        matches!(self.state, FragmentState::Complete)
    }

    fn is_secondary(&self) -> bool {
        self.is_secondary
    }

    fn completes_with(&self, other: &Self) -> bool {
        if !self.is_complete() || !other.is_complete() {
            return false;
        }
        if self.is_secondary() && other.is_secondary() {
            return false;
        }
        if !PaiScheme::is_group_equal(&self.group, &other.group) {
            return false;
        }
        true
    }
}

#[derive(Debug, Clone, Copy)]
pub enum IntersectionAction {
    DoNothing,
    BindReadCap,
    RequestSubspaceCap,
    ReplyReadCap,
}

impl IntersectionAction {
    pub fn new_primary(is_most_specific: bool) -> Self {
        if is_most_specific {
            IntersectionAction::BindReadCap
        } else {
            IntersectionAction::ReplyReadCap
        }
    }

    pub fn new_secondary(is_most_specific: bool) -> Self {
        if is_most_specific {
            IntersectionAction::RequestSubspaceCap
        } else {
            IntersectionAction::DoNothing
        }
    }
}
