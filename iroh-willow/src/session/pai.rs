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
use futures_lite::{Stream, StreamExt};
use genawaiter::GeneratorState;
use tracing::{debug, trace};

use crate::{
    proto::{
        grouping::SubspaceArea,
        pai::{Fragment, FragmentKind, FragmentSet, PaiScheme, PsiGroup, PsiScalar},
        sync::{
            IntersectionHandle, IntersectionMessage, Message, PaiBindFragment, PaiReplyFragment,
            PaiRequestSubspaceCapability, ReadAuthorisation, SubspaceCapability,
        },
        willow::{NamespaceId, Path},
    },
    session::{
        resource::{MissingResource, ResourceMap},
        Error, Scope, Session,
    },
    store::{traits::Storage, Store},
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
pub struct PaiIntersection {
    pub authorisation: ReadAuthorisation,
    pub handle: IntersectionHandle,
}

#[derive(Debug)]
pub enum Input {
    SubmitAuthorisation(ReadAuthorisation),
    ReceivedMessage(Result<IntersectionMessage, Error>),
    ReceivedSubspaceCapRequest(IntersectionHandle),
    ReceivedVerifiedSubspaceCapReply(IntersectionHandle, NamespaceId),
    ReceivedReadCapForIntersection(IntersectionHandle),
}

#[derive(Debug)]
pub enum Output {
    SendMessage(Message),
    NewIntersection(PaiIntersection),
    SignAndSendSubspaceCap(IntersectionHandle, SubspaceCapability),
}

#[derive(derive_more::Debug)]
pub struct PaiFinder {
    #[debug("Co")]
    co: genawaiter::rc::Co<Output>,
    scalar: PsiScalar,
    fragments_info: HashMap<IntersectionHandle, LocalFragmentInfo>,
    our_intersection_handles: ResourceMap<IntersectionHandle, GroupState>,
    their_intersection_handles: ResourceMap<IntersectionHandle, GroupState>,
    requested_subspace_cap_handles: HashSet<IntersectionHandle>,
}

impl PaiFinder {
    pub async fn run_with_session<S: Storage>(
        session: Session,
        store: Store<S>,
        inbox: impl Stream<Item = Input> + Unpin,
    ) -> Result<(), Error> {
        let mut gen = genawaiter::rc::Gen::new(|co| PaiFinder::new(co).run(inbox));
        loop {
            match gen.async_resume().await {
                GeneratorState::Yielded(output) => match output {
                    Output::SendMessage(message) => session.send(message).await?,
                    Output::NewIntersection(intersection) => {
                        session.push_pai_intersection(intersection)
                    }
                    Output::SignAndSendSubspaceCap(handle, cap) => {
                        let message =
                            session.sign_subspace_capabiltiy(store.secrets(), &cap, handle)?;
                        session.send(Box::new(message)).await?;
                    }
                },
                GeneratorState::Complete(res) => break res,
            }
        }
    }

    #[cfg(test)]
    pub async fn run_with_sink(
        inbox: impl Stream<Item = Input> + Unpin,
        mut outbox: impl futures_util::Sink<Output, Error = Error> + Unpin,
    ) -> Result<(), Error> {
        use futures_util::SinkExt;
        let mut gen = genawaiter::rc::Gen::new(|co| PaiFinder::new(co).run(inbox));
        loop {
            let y = gen.async_resume().await;
            match y {
                GeneratorState::Yielded(output) => outbox.send(output).await?,
                GeneratorState::Complete(res) => break res,
            }
        }
    }

    pub fn new(co: genawaiter::rc::Co<Output>) -> Self {
        Self {
            co,
            scalar: PaiScheme::get_scalar(),
            our_intersection_handles: Default::default(),
            their_intersection_handles: Default::default(),
            fragments_info: Default::default(),
            requested_subspace_cap_handles: Default::default(),
        }
    }

    pub async fn run(mut self, mut inbox: impl Stream<Item = Input> + Unpin) -> Result<(), Error> {
        while let Some(input) = inbox.next().await {
            trace!("pai input {input:?}");
            self.input(input).await?;
        }
        Ok(())
    }

    async fn input(&mut self, input: Input) -> Result<(), Error> {
        match input {
            Input::SubmitAuthorisation(auth) => self.submit_autorisation(auth).await,
            Input::ReceivedMessage(message) => match message? {
                IntersectionMessage::BindFragment(message) => self.receive_bind(message).await?,
                IntersectionMessage::ReplyFragment(message) => self.receive_reply(message).await?,
            },
            Input::ReceivedSubspaceCapRequest(handle) => {
                self.received_subspace_cap_request(handle).await?
            }
            Input::ReceivedVerifiedSubspaceCapReply(handle, namespace) => {
                self.received_verified_subspace_cap_reply(handle, namespace)
                    .await?
            }
            Input::ReceivedReadCapForIntersection(handle) => {
                self.received_read_cap_for_intersection(handle).await?
            }
        }
        Ok(())
    }

    async fn submit_autorisation(&mut self, authorisation: ReadAuthorisation) {
        trace!(?authorisation, "pai submit auth");
        let read_cap = authorisation.read_cap();
        let fragment_kit = PaiScheme::get_fragment_kit(read_cap);
        let fragment_set = fragment_kit.into_fragment_set();
        match fragment_set {
            FragmentSet::Complete(pairs) => {
                let last = pairs.len().wrapping_sub(1);
                for (i, pair) in pairs.into_iter().enumerate() {
                    self.submit_fragment(
                        authorisation.clone(),
                        Fragment::Pair(pair),
                        FragmentKind::Primary,
                        i == last,
                    )
                    .await;
                }
            }
            FragmentSet::Selective { primary, secondary } => {
                let last = primary.len().wrapping_sub(1);
                for (i, triple) in primary.into_iter().enumerate() {
                    self.submit_fragment(
                        authorisation.clone(),
                        Fragment::Triple(triple),
                        FragmentKind::Primary,
                        i == last,
                    )
                    .await;
                }
                let last = secondary.len().wrapping_sub(1);
                for (i, pair) in secondary.into_iter().enumerate() {
                    self.submit_fragment(
                        authorisation.clone(),
                        Fragment::Pair(pair),
                        FragmentKind::Secondary,
                        i == last,
                    )
                    .await;
                }
            }
        }
    }

    async fn submit_fragment(
        &mut self,
        authorisation: ReadAuthorisation,
        fragment: Fragment,
        kind: FragmentKind,
        is_most_specific: bool,
    ) -> IntersectionHandle {
        let unmixed = PaiScheme::hash_into_group(&fragment);
        let multiplied = PaiScheme::scalar_mult(unmixed, self.scalar);
        let group_state = GroupState::new_pending(multiplied, kind.is_secondary());
        let message = group_state.to_bind_fragment_message();
        let handle = self.our_intersection_handles.bind(group_state);
        let info = LocalFragmentInfo::new(authorisation, fragment, kind, is_most_specific);
        self.fragments_info.insert(handle, info);
        self.out(Output::SendMessage(message.into())).await;
        handle
    }

    async fn receive_bind(&mut self, message: PaiBindFragment) -> Result<()> {
        let PaiBindFragment {
            group_member,
            is_secondary,
        } = message;
        let unmixed = PsiGroup::from_bytes(group_member)?;
        let multiplied = PaiScheme::scalar_mult(unmixed, self.scalar);
        let group_state = GroupState::new_complete(multiplied, is_secondary);
        let handle = self.their_intersection_handles.bind(group_state);
        let message = PaiReplyFragment {
            handle,
            group_member: multiplied.to_bytes(),
        };
        self.out(Output::SendMessage(message.into())).await;
        self.check_for_intersection(handle, Scope::Theirs).await?;
        Ok(())
    }

    async fn receive_reply(&mut self, message: PaiReplyFragment) -> Result<()> {
        let PaiReplyFragment {
            handle,
            group_member,
        } = message;
        let group = PsiGroup::from_bytes(group_member)?;
        let our_state = self.our_intersection_handles.try_get(&handle)?;
        let next_state = GroupState::new_complete(group, our_state.is_secondary);
        self.our_intersection_handles.update(handle, next_state)?;
        self.check_for_intersection(handle, Scope::Ours).await?;
        Ok(())
    }

    async fn check_for_intersection(
        &mut self,
        handle: IntersectionHandle,
        scope: Scope,
    ) -> Result<(), Error> {
        let store_to_get_handle_from = match scope {
            Scope::Ours => &self.our_intersection_handles,
            Scope::Theirs => &self.their_intersection_handles,
        };
        let store_to_check_against = match scope {
            Scope::Ours => &self.their_intersection_handles,
            Scope::Theirs => &self.our_intersection_handles,
        };
        let intersection = store_to_get_handle_from.try_get(&handle)?;
        if !intersection.is_complete() {
            return Ok(());
        }

        // Here we are looping through the whole contents of the handle store because...
        // otherwise we need to build a special handle store just for intersections.
        // Which we might do one day, but I'm not convinced it's worth it yet.
        for (other_handle, other_intersection) in store_to_check_against.iter() {
            if !other_intersection.completes_with(intersection) {
                continue;
            }

            // If there is an intersection, check what we have to do!
            let our_handle = match scope {
                Scope::Ours => handle,
                Scope::Theirs => *other_handle,
            };

            let info = self.fragment_info(&our_handle)?;
            match info.on_intersection {
                OnIntersection::BindReadCap => {
                    let intersection = info.to_pai_intersection(our_handle);
                    self.out(Output::NewIntersection(intersection)).await;
                }
                OnIntersection::RequestSubspaceCap => {
                    self.requested_subspace_cap_handles.insert(our_handle);
                    let message = PaiRequestSubspaceCapability { handle };
                    self.out(Output::SendMessage(message.into())).await;
                }
                OnIntersection::ReplyReadCap | OnIntersection::DoNothing => {}
            }
        }

        Ok(())
    }

    async fn received_read_cap_for_intersection(
        &mut self,
        their_handle: IntersectionHandle,
    ) -> Result<()> {
        let their_intersection = self.their_intersection_handles.try_get(&their_handle)?;
        for (our_handle, our_intersection) in self.our_intersection_handles.iter() {
            if !our_intersection.completes_with(their_intersection) {
                continue;
            }
            let fragment_info = self.fragment_info(our_handle)?;
            if let OnIntersection::ReplyReadCap = fragment_info.on_intersection {
                let intersection = fragment_info.to_pai_intersection(*our_handle);
                self.out(Output::NewIntersection(intersection)).await;
            }
        }
        Ok(())
    }

    async fn received_verified_subspace_cap_reply(
        &mut self,
        handle: IntersectionHandle,
        namespace_id: NamespaceId,
    ) -> Result<(), PaiError> {
        if !self.requested_subspace_cap_handles.remove(&handle) {
            return Err(PaiError::SubspaceCapRequestForInvalidHandle);
        }
        let _ = self.our_intersection_handles.try_get(&handle)?;
        let fragment_info = self.fragment_info(&handle)?;
        if fragment_info.namespace_id != namespace_id {
            return Err(PaiError::SubspaceCapRequestForWrongNamespace);
        }
        let intersection = fragment_info.to_pai_intersection(handle);
        self.out(Output::NewIntersection(intersection)).await;
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
            let fragment_info = self.fragment_info(our_handle)?;
            if let Some(cap) = fragment_info.authorisation.subspace_cap() {
                self.out(Output::SignAndSendSubspaceCap(handle, cap.clone()))
                    .await;
            }
        }
        Ok(())
    }

    async fn out(&self, out: Output) {
        self.co.yield_(out).await
    }

    fn fragment_info(
        &self,
        handle: &IntersectionHandle,
    ) -> Result<&LocalFragmentInfo, MissingResource> {
        self.fragments_info
            .get(handle)
            .ok_or(MissingResource((*handle).into()))
    }
}

#[derive(Debug)]
pub struct LocalFragmentInfo {
    on_intersection: OnIntersection,
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
    fn new(
        authorisation: ReadAuthorisation,
        fragment: Fragment,
        kind: FragmentKind,
        is_most_specific: bool,
    ) -> Self {
        let (namespace_id, subspace, path) = fragment.into_parts();
        let on_intersection = OnIntersection::new(kind, is_most_specific);
        LocalFragmentInfo {
            on_intersection,
            authorisation,
            namespace_id,
            path,
            subspace,
        }
    }

    fn to_pai_intersection(&self, handle: IntersectionHandle) -> PaiIntersection {
        PaiIntersection {
            authorisation: self.authorisation.clone(),
            handle,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum PendingState {
    Pending,
    Complete,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct GroupState {
    group: PsiGroup,
    state: PendingState,
    is_secondary: bool,
}

impl GroupState {
    fn new_pending(group: PsiGroup, is_secondary: bool) -> Self {
        Self {
            group,
            state: PendingState::Pending,
            is_secondary,
        }
    }
    fn new_complete(group: PsiGroup, is_secondary: bool) -> Self {
        Self {
            group,
            state: PendingState::Complete,
            is_secondary,
        }
    }
}

impl GroupState {
    fn to_bind_fragment_message(&self) -> PaiBindFragment {
        PaiBindFragment {
            group_member: self.group.to_bytes(),
            is_secondary: self.is_secondary,
        }
    }

    fn is_complete(&self) -> bool {
        matches!(self.state, PendingState::Complete)
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
pub enum OnIntersection {
    DoNothing,
    BindReadCap,
    RequestSubspaceCap,
    ReplyReadCap,
}

impl OnIntersection {
    pub fn new(fragment_kind: FragmentKind, is_most_specific: bool) -> Self {
        match (fragment_kind, is_most_specific) {
            (FragmentKind::Primary, true) => OnIntersection::BindReadCap,
            (FragmentKind::Primary, false) => OnIntersection::ReplyReadCap,
            (FragmentKind::Secondary, true) => OnIntersection::RequestSubspaceCap,
            (FragmentKind::Secondary, false) => OnIntersection::DoNothing,
        }
    }
}

#[cfg(test)]
mod tests {
    use futures_util::SinkExt;
    use rand_core::SeedableRng;
    use tokio::task::{spawn_local, JoinHandle};
    use tracing::{error_span, Instrument, Span};

    use crate::{
        proto::{
            keys::{NamespaceKind, NamespaceSecretKey, UserSecretKey},
            sync::{
                IntersectionMessage, Message, PaiBindFragment, PaiReplyFragment, ReadAuthorisation,
            },
        },
        session::Error,
    };

    use super::{Input, Output, PaiFinder};

    #[tokio::test]
    async fn pai_smoke() {
        iroh_test::logging::setup_multithreaded();
        let local = tokio::task::LocalSet::new();
        local.run_until(pai_smoke_inner()).await
    }
    async fn pai_smoke_inner() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(1);

        let namespace = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);

        let alfie_secret = UserSecretKey::generate(&mut rng);
        let betty_secret = UserSecretKey::generate(&mut rng);
        let alfie_public = alfie_secret.public_key();
        let betty_public = betty_secret.public_key();

        let auth_alfie = ReadAuthorisation::new_owned(&namespace, alfie_public);
        let auth_betty = ReadAuthorisation::new_owned(&namespace, betty_public);

        let (alfie, betty) = Handle::create_two();

        alfie.submit(auth_alfie.clone()).await;
        betty.submit(auth_betty.clone()).await;

        transfer::<PaiBindFragment>(&alfie, &betty).await;
        transfer::<PaiBindFragment>(&betty, &alfie).await;
        transfer::<PaiReplyFragment>(&alfie, &betty).await;
        transfer::<PaiReplyFragment>(&betty, &alfie).await;

        assert_eq!(alfie.next_intersection().await, auth_alfie);
        assert_eq!(betty.next_intersection().await, auth_betty);

        alfie.join().await;
        betty.join().await;
    }

    async fn transfer<T: TryFrom<Message> + Into<IntersectionMessage>>(from: &Handle, to: &Handle) {
        let message = from.next_message::<T>().await;
        let message: IntersectionMessage = message.into();
        to.receive(message).await;
    }

    struct Handle {
        task: JoinHandle<Result<(), Error>>,
        input: flume::Sender<Input>,
        output: flume::Receiver<Output>,
    }
    impl Handle {
        pub fn create_two() -> (Self, Self) {
            (
                Self::new(error_span!("alfie")),
                Self::new(error_span!("betty")),
            )
        }

        pub fn new(span: Span) -> Self {
            let (input, input_rx) = flume::bounded(1);
            let (output_tx, output) = flume::bounded(1);
            let outbox = output_tx
                .into_sink()
                .sink_map_err(|_| Error::InvalidState("failed to send"));
            let inbox = input_rx.into_stream();
            let task = spawn_local(
                async move { PaiFinder::run_with_sink(inbox, outbox).await }.instrument(span),
            );
            Handle {
                input,
                output,
                task,
            }
        }

        pub async fn input(&self, input: Input) {
            self.input.send_async(input).await.unwrap();
        }

        pub async fn submit(&self, auth: ReadAuthorisation) {
            self.input(Input::SubmitAuthorisation(auth)).await
        }

        pub async fn receive(&self, message: impl Into<IntersectionMessage>) {
            self.input(Input::ReceivedMessage(Ok(message.into()))).await
        }

        pub async fn next(&self) -> Output {
            self.output.recv_async().await.unwrap()
        }

        pub async fn next_intersection(&self) -> ReadAuthorisation {
            match self.next().await {
                Output::NewIntersection(intersection) => intersection.authorisation,
                out => panic!("expected NewIntersection but got {out:?}"),
            }
        }

        pub async fn next_message<T: TryFrom<Message>>(&self) -> T {
            match self.next().await {
                Output::SendMessage(message) => match T::try_from(message) {
                    Err(_err) => panic!("wrong message type"),
                    Ok(message) => message,
                },
                other => panic!("expected SendMessage but got {other:?}"),
            }
        }

        pub async fn join(self) {
            drop(self.input);
            drop(self.output);
            self.task.await.unwrap().unwrap()
        }
    }
}
