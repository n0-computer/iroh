use std::{
    cell::RefCell,
    rc::Rc,
};



use crate::{
    proto::{
        grouping::{Area, AreaOfInterest},
        keys::NamespaceId,
        sync::{AreaOfInterestHandle, CapabilityHandle, ReadCapability, SetupBindAreaOfInterest},
    },
    session::{channels::ChannelSenders, resource::ResourceMap, Error, Scope},
};

/// Intersection between two areas of interest.
#[derive(Debug, Clone)]
pub struct AoiIntersection {
    pub our_handle: AreaOfInterestHandle,
    pub their_handle: AreaOfInterestHandle,
    pub intersection: Area,
    pub namespace: NamespaceId,
}

#[derive(Debug)]
struct AoiInfo {
    aoi: AreaOfInterest,
    namespace: NamespaceId,
    // authorisation: CapabilityHandle,
    // state: State,
}

impl AoiInfo {
    fn area(&self) -> &Area {
        &self.aoi.area
    }
}

// #[derive(Debug, Default)]
// enum State {
//     #[default]
//     Submitted,
//     Started {
//         pending_ranges: HashSet<u64>,
//     },
//     Complete,
// }

#[derive(Debug, Default, Clone)]
pub struct AoiFinder(Rc<RefCell<Inner>>);

#[derive(Debug, Default)]
struct Inner {
    our_handles: ResourceMap<AreaOfInterestHandle, AoiInfo>,
    their_handles: ResourceMap<AreaOfInterestHandle, AoiInfo>,
    // queue: Queue<AoiIntersection>,
    subscribers: Vec<flume::Sender<AoiIntersection>>,
}

impl AoiFinder {
    pub fn close(&self) {
        let mut inner = self.0.borrow_mut();
        inner.subscribers.drain(..);
    }
    pub fn subscribe(&self) -> flume::Receiver<AoiIntersection> {
        let (tx, rx) = flume::bounded(128);
        self.0.borrow_mut().subscribers.push(tx);
        rx
    }
    pub async fn bind_and_send_ours(
        &self,
        sender: &ChannelSenders,
        namespace: NamespaceId,
        aoi: AreaOfInterest,
        authorisation: CapabilityHandle,
    ) -> Result<(), Error> {
        self.bind_ours(namespace, aoi.clone())?;
        let msg = SetupBindAreaOfInterest {
            area_of_interest: aoi,
            authorisation,
        };
        sender.send(msg).await?;
        Ok(())
    }

    pub fn bind_ours(&self, namespace: NamespaceId, aoi: AreaOfInterest) -> Result<(), Error> {
        self.0
            .borrow_mut()
            .bind_validated_area_of_interest(Scope::Ours, namespace, aoi)
    }

    pub fn validate_and_bind_theirs(
        &self,
        their_cap: &ReadCapability,
        aoi: AreaOfInterest,
    ) -> Result<(), Error> {
        their_cap.try_granted_area(&aoi.area)?;
        self.0.borrow_mut().bind_validated_area_of_interest(
            Scope::Theirs,
            their_cap.granted_namespace().id(),
            aoi,
        )?;
        Ok(())
    }

    // pub async fn authorise_range_eventually(
    //     &self,
    //     range: &ThreeDRange,
    //     receiver_handle: AreaOfInterestHandle,
    //     sender_handle: AreaOfInterestHandle,
    // ) -> Result<NamespaceId, Error> {
    //     poll_fn(|cx| {
    //         let mut inner = self.0.borrow_mut();
    //         Pin::new(&mut inner).poll_authorise_range_eventually(
    //             range,
    //             receiver_handle,
    //             sender_handle,
    //             cx,
    //         )
    //     })
    //     .await
    // }
}

impl Inner {
    pub fn bind_validated_area_of_interest(
        &mut self,
        scope: Scope,
        namespace: NamespaceId,
        aoi: AreaOfInterest,
    ) -> Result<(), Error> {
        // capability.try_granted_area(&msg.area_of_interest.area)?;
        // let namespace = *capability.granted_namespace();
        let area = aoi.area.clone();
        let info = AoiInfo {
            aoi,
            // authorisation: msg.authorisation,
            namespace,
            // state: State::Submitted,
        };
        let handle = match scope {
            Scope::Ours => self.our_handles.bind(info),
            Scope::Theirs => self.their_handles.bind(info),
        };

        let other_resources = match scope {
            Scope::Ours => &self.their_handles,
            Scope::Theirs => &self.our_handles,
        };

        // TODO: If we stored the AoIs by namespace we would need to iterate less.
        for (candidate_handle, candidate) in other_resources.iter() {
            let candidate_handle = *candidate_handle;
            // Ignore areas without a capability.
            // let Some(cap) = other_resources.capabilities.get(&candidate.authorisation) else {
            //     continue;
            // };
            // Ignore areas for a different namespace.
            // if *cap.granted_namespace() != namespace {
            //     continue;
            // }
            if candidate.namespace != namespace {
                continue;
            }
            // Check if we have an intersection.
            if let Some(intersection) = candidate.area().intersection(&area) {
                // We found an intersection!
                let (our_handle, their_handle) = match scope {
                    Scope::Ours => (handle, candidate_handle),
                    Scope::Theirs => (candidate_handle, handle),
                };
                let intersection = AoiIntersection {
                    our_handle,
                    their_handle,
                    intersection,
                    namespace,
                };
                self.subscribers
                    .retain(|sender| sender.send(intersection.clone()).is_ok());
                // for subscriber in self.subscribers {
                //     // TODO: async, no panic
                //     subscriber.send(intersection).unwrap();
                // }
                // self.queue.push_back(intersection);
            }
        }
        Ok(())
    }

    // pub fn poll_authorise_range_eventually(
    //     &mut self,
    //     range: &ThreeDRange,
    //     receiver_handle: AreaOfInterestHandle,
    //     sender_handle: AreaOfInterestHandle,
    //     cx: &mut Context<'_>,
    // ) -> Poll<Result<NamespaceId, Error>> {
    //     let their_aoi = ready!(self.their_handles.poll_get_eventually(sender_handle, cx));
    //     let our_aoi = self.our_handles.try_get(&receiver_handle)?;
    //     let res = if our_aoi.namespace != their_aoi.namespace {
    //         Err(Error::AreaOfInterestNamespaceMismatch)
    //     } else if !our_aoi.area().includes_range(range) || !their_aoi.area().includes_range(range) {
    //         Err(Error::RangeOutsideCapability)
    //     } else {
    //         Ok(our_aoi.namespace)
    //     };
    //     Poll::Ready(res)
    // }
}

// impl Stream for AoiFinder {
//     type Item = AoiIntersection;
//
//     fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
//         let mut queue = &mut self.0.borrow_mut().queue;
//         Pin::new(&mut queue).poll_next(cx)
//     }
// }
