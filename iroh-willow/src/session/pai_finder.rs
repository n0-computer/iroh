//! Private Area Intersection finder
//!
//! As defined by the willow spec: [Private Area Intersection](https://willowprotocol.org/specs/pai/index.html)
//!
//! Partly ported from the implementation in [earthstar] and [willow].
//!
//! Licensed under LGPL and ported into this MIT/Apache codebase with explicit permission
//! from the original author (gwil).
//!
//! [earthstar]: https://github.com/earthstar-project/willow-js/blob/0db4b9ec7710fb992ab75a17bd8557040d9a1062/src/wgps/pai/pai_finder.ts
//! [willow]: https://github.com/earthstar-project/earthstar/blob/16d6d4028c22fdbb72f7395013b29be7dcd9217a/src/schemes/schemes.ts#L662
//!

use std::collections::{HashMap, HashSet};

use anyhow::Result;
use futures_lite::{Stream, StreamExt};

use tracing::{debug, trace};

use crate::{
    proto::{
        data_model::{NamespaceId, Path},
        grouping::AreaSubspace,
        meadowcap::{ReadAuthorisation, SubspaceCapability},
        pai::{Fragment, FragmentKind, FragmentSet, PaiScheme, PsiGroup, PsiScalar},
        wgps::{
            IntersectionHandle, IntersectionMessage, Message, PaiBindFragment, PaiReplyFragment,
            PaiRequestSubspaceCapability,
        },
    },
    session::{
        resource::{MissingResource, ResourceMap, Scope},
        Error,
    },
    util::gen_stream::GenStream,
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
    Established,
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
    submitted: HashSet<ReadAuthorisation>,
    pending: Option<HashSet<ReadAuthorisation>>,
}

impl PaiFinder {
    /// Run the [`PaiFinder`].
    ///
    /// The returned stream is a generator, so it must be polled repeatedly for the [`PaiFinder`]
    /// to progress.
    ///
    /// Submit inputs through the inbox. The [`PaiFinder`] will not yield any outputs until
    /// [`Input::Established`]. Authorisations submitted prior are queued and will be yielded after
    /// the establish input.
    pub fn run_gen(
        inbox: impl Stream<Item = Input> + Unpin,
    ) -> impl Stream<Item = Result<Output, Error>> {
        GenStream::new(|co| PaiFinder::new(co).run(inbox))
    }

    #[cfg(test)]
    pub async fn run_with_sink(
        inbox: impl Stream<Item = Input> + Unpin,
        mut outbox: impl futures_util::Sink<Output, Error = Error> + Unpin,
    ) -> Result<(), Error> {
        use futures_util::SinkExt;
        let mut gen = Self::run_gen(inbox);
        while let Some(output) = gen.try_next().await? {
            outbox.send(output).await?;
        }
        Ok(())
    }

    pub fn new(co: genawaiter::rc::Co<Output>) -> Self {
        Self {
            co,
            scalar: PaiScheme::get_scalar(),
            our_intersection_handles: Default::default(),
            their_intersection_handles: Default::default(),
            fragments_info: Default::default(),
            requested_subspace_cap_handles: Default::default(),
            submitted: Default::default(),
            pending: Some(Default::default()),
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
            Input::SubmitAuthorisation(auth) => {
                if let Some(pending) = self.pending.as_mut() {
                    pending.insert(auth);
                } else {
                    self.submit_authorisation(auth).await;
                }
            }
            Input::Established => {
                if let Some(mut pending) = self.pending.take() {
                    for authorisation in pending.drain() {
                        self.submit_authorisation(authorisation).await;
                    }
                }
            }
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

    async fn submit_authorisation(&mut self, authorisation: ReadAuthorisation) {
        if !self.submitted.insert(authorisation.clone()) {
            return;
        }
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
    subspace: AreaSubspace,
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
    use rand_core::{CryptoRngCore, SeedableRng};
    use tokio::task::{spawn_local, JoinHandle, LocalSet};
    use tokio_stream::wrappers::ReceiverStream;
    use tokio_util::sync::PollSender;
    use tracing::{error_span, Instrument, Span};

    use crate::{
        proto::{
            data_model::{Path, PathExt},
            grouping::{Area, AreaSubspace},
            keys::{NamespaceKind, NamespaceSecretKey, UserId, UserSecretKey},
            meadowcap::ReadAuthorisation,
            wgps::{
                IntersectionMessage, Message, PaiBindFragment, PaiReplyFragment,
                PaiRequestSubspaceCapability,
            },
        },
        session::{pai_finder::PaiIntersection, Error},
    };

    use super::{Input, Output, PaiFinder};

    #[tokio::test]
    async fn pai_smoke() {
        let _guard = iroh_test::logging::setup();
        LocalSet::new().run_until(pai_smoke_inner()).await
    }
    async fn pai_smoke_inner() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(1);
        let namespace_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);

        let (_, alfie_public) = keypair(&mut rng);
        let (_, betty_public) = keypair(&mut rng);

        let auth_alfie = ReadAuthorisation::new_owned(&namespace_secret, alfie_public).unwrap();
        let auth_betty = ReadAuthorisation::new_owned(&namespace_secret, betty_public).unwrap();

        let (mut alfie, mut betty) = Handle::create_two();

        alfie.submit(auth_alfie.clone()).await;
        betty.submit(auth_betty.clone()).await;

        transfer::<PaiBindFragment>(&mut alfie, &betty).await;
        transfer::<PaiBindFragment>(&mut betty, &alfie).await;
        transfer::<PaiReplyFragment>(&mut alfie, &betty).await;
        transfer::<PaiReplyFragment>(&mut betty, &alfie).await;

        assert_eq!(alfie.next_intersection().await.authorisation, auth_alfie);
        assert_eq!(betty.next_intersection().await.authorisation, auth_betty);

        alfie.join().await;
        betty.join().await;
    }

    #[tokio::test]
    async fn pai_subspace() {
        let _guard = iroh_test::logging::setup();
        LocalSet::new().run_until(pai_subspace_inner()).await
    }
    async fn pai_subspace_inner() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(1);
        let namespace = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);

        let (root_secret, root_public) = keypair(&mut rng);
        let root_auth = ReadAuthorisation::new_owned(&namespace, root_public).unwrap();

        let (_, alfie_public) = keypair(&mut rng);
        let (_, betty_public) = keypair(&mut rng);
        let (_, gemma_public) = keypair(&mut rng);

        let alfie_area = Area::new(
            AreaSubspace::Id(gemma_public),
            Path::new_empty(),
            Default::default(),
        );
        let alfie_auth = root_auth
            .delegate(&root_secret, alfie_public, alfie_area)
            .unwrap();
        assert!(alfie_auth.subspace_cap().is_none());

        let betty_area = Area::new(
            AreaSubspace::Any,
            Path::from_bytes(&[b"chess"]).unwrap(),
            Default::default(),
        );
        let betty_auth = root_auth
            .delegate(&root_secret, betty_public, betty_area)
            .unwrap();
        assert!(betty_auth.subspace_cap().is_some());

        let (mut alfie, mut betty) = Handle::create_two();

        alfie.submit(alfie_auth.clone()).await;
        betty.submit(betty_auth.clone()).await;

        transfer::<PaiBindFragment>(&mut alfie, &betty).await;
        transfer::<PaiBindFragment>(&mut betty, &alfie).await;

        transfer::<PaiBindFragment>(&mut alfie, &betty).await;
        transfer::<PaiBindFragment>(&mut betty, &alfie).await;

        transfer::<PaiReplyFragment>(&mut alfie, &betty).await;
        transfer::<PaiReplyFragment>(&mut betty, &alfie).await;

        transfer::<PaiReplyFragment>(&mut alfie, &betty).await;
        transfer::<PaiReplyFragment>(&mut betty, &alfie).await;

        let next: PaiRequestSubspaceCapability = alfie.next_message().await;
        betty
            .input(Input::ReceivedSubspaceCapRequest(next.handle))
            .await;

        let (handle, cap) = match betty.next().await {
            Output::SignAndSendSubspaceCap(handle, cap) => (handle, cap),
            other => panic!("expected SignAndSendSubspaceCap but got {other:?}"),
        };

        assert_eq!(&cap, betty_auth.subspace_cap().unwrap());
        let namespace = cap.granted_namespace();
        alfie
            .input(Input::ReceivedVerifiedSubspaceCapReply(handle, *namespace))
            .await;

        let next = alfie.next_intersection().await;
        assert_eq!(next.authorisation, alfie_auth);
        betty
            .input(Input::ReceivedReadCapForIntersection(next.handle))
            .await;

        let next = betty.next_intersection().await;
        assert_eq!(next.authorisation, betty_auth);

        alfie.join().await;
        betty.join().await;
    }

    fn keypair<R: CryptoRngCore + ?Sized>(rng: &mut R) -> (UserSecretKey, UserId) {
        let secret = UserSecretKey::generate(rng);
        let public = secret.public_key();
        (secret, public.id())
    }

    async fn transfer<T: TryFrom<Message> + Into<IntersectionMessage>>(
        from: &mut Handle,
        to: &Handle,
    ) {
        let message = from.next_message::<T>().await;
        let message: IntersectionMessage = message.into();
        to.receive(message).await;
    }

    struct Handle {
        task: JoinHandle<Result<(), Error>>,
        input: tokio::sync::mpsc::Sender<Input>,
        output: tokio::sync::mpsc::Receiver<Output>,
    }

    impl Handle {
        pub fn create_two() -> (Self, Self) {
            (
                Self::new(error_span!("alfie")),
                Self::new(error_span!("betty")),
            )
        }

        pub fn new(span: Span) -> Self {
            let (input, input_rx) = tokio::sync::mpsc::channel(1);
            let (output_tx, output) = tokio::sync::mpsc::channel(1);
            input.try_send(Input::Established).expect("has capacity");
            let outbox =
                PollSender::new(output_tx).sink_map_err(|_| Error::InvalidState("failed to send"));
            let inbox = ReceiverStream::new(input_rx);
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
            self.input.send(input).await.unwrap();
        }

        pub async fn submit(&self, auth: ReadAuthorisation) {
            self.input(Input::SubmitAuthorisation(auth)).await
        }

        pub async fn receive(&self, message: impl Into<IntersectionMessage>) {
            self.input(Input::ReceivedMessage(Ok(message.into()))).await
        }

        pub async fn next(&mut self) -> Output {
            self.output.recv().await.unwrap()
        }

        pub async fn next_intersection(&mut self) -> PaiIntersection {
            match self.next().await {
                Output::NewIntersection(intersection) => intersection,
                out => panic!("expected NewIntersection but got {out:?}"),
            }
        }

        pub async fn next_message<T: TryFrom<Message>>(&mut self) -> T {
            match self.next().await {
                Output::SendMessage(message) => {
                    let dbg = format!("{}", message);
                    match T::try_from(message) {
                        Err(_err) => panic!(
                            "wrong message type: expected {} but got {:?}",
                            std::any::type_name::<T>(),
                            dbg
                        ),
                        Ok(message) => message,
                    }
                }
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
