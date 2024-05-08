use std::collections::{HashMap, VecDeque};

use crate::{
    proto::wgps::{
        AreaOfInterestHandle, CapabilityHandle, IsHandle, ReadCapability, ResourceHandle,
        SetupBindAreaOfInterest, StaticToken, StaticTokenHandle,
    },
    store::actor::Notifier,
};

use super::Error;

#[derive(Debug, Default)]
pub struct ScopedResources {
    pub capabilities: ResourceMap<CapabilityHandle, ReadCapability>,
    pub areas_of_interest: ResourceMap<AreaOfInterestHandle, SetupBindAreaOfInterest>,
    pub static_tokens: ResourceMap<StaticTokenHandle, StaticToken>,
}
impl ScopedResources {
    pub fn register_notify(&mut self, handle: ResourceHandle, notify: Notifier) {
        tracing::debug!(?handle, "register_notify");
        match handle {
            ResourceHandle::AreaOfInterest(h) => self.areas_of_interest.register_notify(h, notify),
            ResourceHandle::Capability(h) => self.capabilities.register_notify(h, notify),
            ResourceHandle::StaticToken(h) => self.static_tokens.register_notify(h, notify),
            ResourceHandle::Intersection(_h) => unimplemented!(),
        }
    }

    //     pub fn get(&self, scope: Scope, handle: &Handle) {
    //         match handle {
    //             Handle::AreaOfInterest(h) => self.areas_of_interest.get(h),
    //             Handle::Intersection(h) => unimplemented!(),
    //             Handle::Capability(h) => self.capabilities.get(h),
    //             Handle::StaticToken(_h) => self.static_tokens.get(h),
    //         }
    //     }
}

#[derive(Debug)]
pub struct ResourceMap<H, R> {
    next_handle: u64,
    map: HashMap<H, Resource<R>>,
    notify: HashMap<H, VecDeque<Notifier>>,
}

impl<H, R> Default for ResourceMap<H, R> {
    fn default() -> Self {
        Self {
            next_handle: 0,
            map: Default::default(),
            notify: Default::default(),
        }
    }
}

impl<H, R> ResourceMap<H, R>
where
    H: IsHandle,
    R: Eq + PartialEq,
{
    pub fn bind(&mut self, resource: R) -> H {
        let handle: H = self.next_handle.into();
        self.next_handle += 1;
        let resource = Resource::new(resource);
        self.map.insert(handle, resource);
        tracing::debug!(?handle, "bind");
        if let Some(mut notify) = self.notify.remove(&handle) {
            tracing::debug!(?handle, "notify {}", notify.len());
            for notify in notify.drain(..) {
                if let Err(err) = notify.notify_sync() {
                    tracing::warn!(?err, "notify failed for {handle:?}");
                }
            }
        }
        handle
    }

    pub fn register_notify(&mut self, handle: H, notifier: Notifier) {
        self.notify.entry(handle).or_default().push_back(notifier)
    }

    pub fn bind_if_new(&mut self, resource: R) -> (H, bool) {
        // TODO: Optimize / find out if reverse index is better than find_map
        if let Some(handle) = self
            .map
            .iter()
            .find_map(|(handle, r)| (r.value == resource).then_some(handle))
        {
            (*handle, false)
        } else {
            let handle = self.bind(resource);
            (handle, true)
        }
    }

    pub fn get(&self, handle: &H) -> Result<&R, Error> {
        self.map
            .get(handle)
            .as_ref()
            .map(|r| &r.value)
            .ok_or_else(|| Error::MissingResource((*handle).into()))
    }

    pub fn get_or_notify(&mut self, handle: &H, notify: impl FnOnce() -> Notifier) -> Option<&R> {
        if let Some(resource) = self.map.get(handle).as_ref().map(|r| &r.value) {
            Some(resource)
        } else {
            self.notify
                .entry(*handle)
                .or_default()
                .push_back((notify)());
            None
        }
    }
}

// #[derive(Debug)]
// enum ResourceState {
//     Active,
//     WeProposedFree,
//     ToBeDeleted,
// }

#[derive(Debug)]
struct Resource<V> {
    value: V,
    // state: ResourceState,
    // unprocessed_messages: usize,
}
impl<V> Resource<V> {
    pub fn new(value: V) -> Self {
        Self {
            value,
            // state: ResourceState::Active,
            // unprocessed_messages: 0,
        }
    }
}

// #[derive(Debug, Default)]
// pub struct Resources {
//     pub ours: ScopedResources,
//     pub theirs: ScopedResources,
// }
//
// impl Resources {
//     pub fn scope(&self, scope: Scope) -> &ScopedResources {
//         match scope {
//             Scope::Ours => &self.ours,
//             Scope::Theirs => &self.theirs,
//         }
//     }
//
//     pub fn scope_mut(&mut self, scope: Scope) -> &mut ScopedResources {
//         match scope {
//             Scope::Ours => &mut self.ours,
//             Scope::Theirs => &mut self.theirs,
//         }
//     }
// }
