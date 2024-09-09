use std::collections::hash_map;

use futures_lite::{Stream, StreamExt};
use genawaiter::rc::Co;

use crate::{
    interest::InterestMap,
    proto::{
        grouping::{Area, AreaOfInterest},
        keys::NamespaceId,
        meadowcap::{ReadAuthorisation, ReadCapability},
        wgps::{
            AreaOfInterestHandle, CapabilityHandle, IntersectionHandle, SetupBindAreaOfInterest,
        },
    },
    session::{
        capabilities::Capabilities,
        pai_finder::PaiIntersection,
        resource::{ResourceMap, Scope},
        Error,
    },
    util::gen_stream::GenStream,
};

/// Intersection between two areas of interest.
#[derive(Debug, Clone)]
pub struct AoiIntersection {
    pub our_handle: AreaOfInterestHandle,
    pub their_handle: AreaOfInterestHandle,
    pub intersection: AreaOfInterest,
    pub namespace: NamespaceId,
}

impl AoiIntersection {
    pub fn id(&self) -> (AreaOfInterestHandle, AreaOfInterestHandle) {
        (self.our_handle, self.their_handle)
    }

    pub fn area(&self) -> &Area {
        &self.intersection.area
    }
}

#[derive(Debug)]
pub enum Input {
    AddInterests(InterestMap),
    PaiIntersection(PaiIntersection),
    ReceivedValidatedAoi {
        namespace: NamespaceId,
        aoi: AreaOfInterest,
    },
}

#[derive(Debug)]
pub enum Output {
    SendMessage(SetupBindAreaOfInterest),
    SubmitAuthorisation(ReadAuthorisation),
    AoiIntersection(AoiIntersection),
    SignAndSendCapability {
        handle: IntersectionHandle,
        capability: ReadCapability,
    },
}

#[derive(derive_more::Debug)]
pub struct IntersectionFinder {
    #[debug("Co")]
    co: Co<Output>,
    caps: Capabilities,
    handles: AoiResources,
    interests: InterestMap,
}

impl IntersectionFinder {
    /// Run the [`IntersectionFinder`].
    ///
    /// The returned stream is a generator, so it must be polled repeatedly to progress.
    pub fn run_gen(
        caps: Capabilities,
        inbox: impl Stream<Item = Input>,
    ) -> impl Stream<Item = Result<Output, Error>> {
        GenStream::new(|co| Self::new(co, caps).run(inbox))
    }

    fn new(co: Co<Output>, caps: Capabilities) -> Self {
        Self {
            co,
            caps,
            interests: Default::default(),
            handles: Default::default(),
        }
    }

    async fn run(mut self, inbox: impl Stream<Item = Input>) -> Result<(), Error> {
        tokio::pin!(inbox);
        while let Some(input) = inbox.next().await {
            match input {
                Input::AddInterests(interests) => self.add_interests(interests).await,
                Input::PaiIntersection(intersection) => {
                    self.on_pai_intersection(intersection).await?;
                }
                Input::ReceivedValidatedAoi { namespace, aoi } => {
                    self.handles
                        .bind_validated(&self.co, Scope::Theirs, namespace, aoi)
                        .await;
                }
            }
        }
        Ok(())
    }

    async fn add_interests(&mut self, interests: InterestMap) {
        for (authorisation, aois) in interests.into_iter() {
            let namespace = authorisation.namespace();
            match self.interests.entry(authorisation.clone()) {
                hash_map::Entry::Occupied(mut entry) => {
                    // The authorisation is already submitted.
                    let existing = entry.get_mut();
                    let capability_handle = self.caps.find_ours(authorisation.read_cap());
                    for aoi in aois {
                        // If the AoI is new, and the capability is already bound, bind and send
                        // the AoI right away.
                        if existing.insert(aoi.clone()) {
                            if let Some(capability_handle) = capability_handle {
                                self.handles
                                    .bind_and_send_ours(&self.co, namespace, capability_handle, aoi)
                                    .await;
                            }
                        }
                    }
                }
                hash_map::Entry::Vacant(entry) => {
                    // The authorisation is new. Submit to the PaiFinder.
                    entry.insert(aois);
                    self.co
                        .yield_(Output::SubmitAuthorisation(authorisation))
                        .await;
                }
            }
        }
    }

    async fn on_pai_intersection(&mut self, intersection: PaiIntersection) -> Result<(), Error> {
        let PaiIntersection {
            authorisation,
            handle,
        } = intersection;
        let aois = self
            .interests
            .get(&authorisation)
            .ok_or(Error::NoKnownInterestsForCapability)?
            .clone();
        let namespace = authorisation.namespace();
        let (capability_handle, is_new) = self.caps.bind_ours(authorisation.read_cap().clone());
        if is_new {
            self.co
                .yield_(Output::SignAndSendCapability {
                    handle,
                    capability: authorisation.read_cap().clone(),
                })
                .await;
        }

        for aoi in aois.into_iter() {
            self.handles
                .bind_and_send_ours(&self.co, namespace, capability_handle, aoi)
                .await;
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
struct AoiResources {
    our_handles: ResourceMap<AreaOfInterestHandle, AoiInfo>,
    their_handles: ResourceMap<AreaOfInterestHandle, AoiInfo>,
}

impl AoiResources {
    async fn bind_and_send_ours(
        &mut self,
        co: &Co<Output>,
        namespace: NamespaceId,
        authorisation: CapabilityHandle,
        aoi: AreaOfInterest,
    ) {
        self.bind_validated(co, Scope::Ours, namespace, aoi.clone())
            .await;
        let msg = SetupBindAreaOfInterest {
            area_of_interest: aoi.into(),
            authorisation,
        };
        co.yield_(Output::SendMessage(msg)).await;
    }
    pub async fn bind_validated(
        &mut self,
        co: &Co<Output>,
        scope: Scope,
        namespace: NamespaceId,
        aoi: AreaOfInterest,
    ) {
        let info = AoiInfo {
            aoi: aoi.clone(),
            namespace,
        };
        let bound_handle = match scope {
            Scope::Ours => self.our_handles.bind(info),
            Scope::Theirs => self.their_handles.bind(info),
        };

        let store_to_check_against = match scope {
            Scope::Ours => &self.their_handles,
            Scope::Theirs => &self.our_handles,
        };

        // TODO: If we stored the AoIs by namespace we would need to iterate less.
        for (other_handle, other_aoi) in store_to_check_against.iter() {
            if other_aoi.namespace != namespace {
                continue;
            }
            let other_handle = *other_handle;
            // Check if we have an intersection.
            if let Some(intersection) = other_aoi.aoi.intersection(&aoi) {
                // We found an intersection!
                let (our_handle, their_handle) = match scope {
                    Scope::Ours => (bound_handle, other_handle),
                    Scope::Theirs => (other_handle, bound_handle),
                };
                let intersection = AoiIntersection {
                    our_handle,
                    their_handle,
                    intersection,
                    namespace,
                };
                co.yield_(Output::AoiIntersection(intersection)).await;
            }
        }
    }
}

#[derive(Debug)]
struct AoiInfo {
    aoi: AreaOfInterest,
    namespace: NamespaceId,
}
