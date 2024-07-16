use std::{cell::RefCell, rc::Rc};

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

#[derive(Debug, Default, Clone)]
pub struct AoiFinder(Rc<RefCell<Inner>>);

pub type AoiIntersectionReceiver = flume::Receiver<AoiIntersection>;

#[derive(Debug, Default)]
struct Inner {
    our_handles: ResourceMap<AreaOfInterestHandle, AoiInfo>,
    their_handles: ResourceMap<AreaOfInterestHandle, AoiInfo>,
    subscribers: Vec<flume::Sender<AoiIntersection>>,
}

impl AoiFinder {
    pub async fn bind_and_send_ours(
        &self,
        sender: &ChannelSenders,
        namespace: NamespaceId,
        aoi: AreaOfInterest,
        authorisation: CapabilityHandle,
    ) -> Result<(), Error> {
        self.bind(Scope::Ours, namespace, aoi.clone())?;
        let msg = SetupBindAreaOfInterest {
            area_of_interest: aoi,
            authorisation,
        };
        sender.send(msg).await?;
        Ok(())
    }

    pub fn validate_and_bind_theirs(
        &self,
        their_cap: &ReadCapability,
        aoi: AreaOfInterest,
    ) -> Result<(), Error> {
        their_cap.try_granted_area(&aoi.area)?;
        self.bind(Scope::Theirs, their_cap.granted_namespace().id(), aoi)?;
        Ok(())
    }

    pub fn subscribe(&self) -> flume::Receiver<AoiIntersection> {
        let (tx, rx) = flume::bounded(2);
        self.0.borrow_mut().subscribers.push(tx);
        rx
    }

    pub fn close(&self) {
        let mut inner = self.0.borrow_mut();
        inner.subscribers.drain(..);
    }

    fn bind(&self, scope: Scope, namespace: NamespaceId, aoi: AreaOfInterest) -> Result<(), Error> {
        let mut inner = self.0.borrow_mut();
        inner.bind_validated_aoi(scope, namespace, aoi)
    }
}

impl Inner {
    pub fn bind_validated_aoi(
        &mut self,
        scope: Scope,
        namespace: NamespaceId,
        aoi: AreaOfInterest,
    ) -> Result<(), Error> {
        // let area = aoi.area.clone();
        let info = AoiInfo {
            aoi: aoi.clone(),
            namespace,
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
            if candidate.namespace != namespace {
                continue;
            }
            let candidate_handle = *candidate_handle;
            // Check if we have an intersection.
            if let Some(intersection) = candidate.aoi.intersection(&aoi) {
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
                // TODO: This can block...
                self.subscribers
                    .retain(|sender| sender.send(intersection.clone()).is_ok());
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
struct AoiInfo {
    aoi: AreaOfInterest,
    namespace: NamespaceId,
}

impl AoiInfo {
    // fn area(&self) -> &Area {
    //     &self.aoi.area
    // }
}
