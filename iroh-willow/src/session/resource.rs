use std::{
    collections::{hash_map, HashMap, VecDeque},
    task::{Context, Poll, Waker},
};

use crate::proto::wgps::{IsHandle, ResourceHandle};

use super::Error;

/// The bind scope for resources.
///
/// Resources are bound by either peer
#[derive(Copy, Clone, Debug)]
pub enum Scope {
    /// Resources bound by ourselves.
    Ours,
    /// Resources bound by the other peer.
    Theirs,
}

#[derive(Debug)]
pub struct ResourceMap<H, R> {
    next_handle: u64,
    map: HashMap<H, Resource<R>>,
    wakers: HashMap<H, VecDeque<Waker>>,
}

impl<H, R> Default for ResourceMap<H, R> {
    fn default() -> Self {
        Self {
            next_handle: 0,
            map: Default::default(),
            wakers: Default::default(),
        }
    }
}

impl<H, R> ResourceMap<H, R>
where
    H: IsHandle,
{
    pub fn iter(&self) -> impl Iterator<Item = (&H, &R)> + '_ {
        self.map.iter().map(|(h, r)| (h, &r.value))
    }

    pub fn bind(&mut self, resource: R) -> H {
        let handle: H = self.next_handle.into();
        self.next_handle += 1;
        let resource = Resource::new(resource);
        self.map.insert(handle, resource);
        tracing::trace!(?handle, "bind");
        if let Some(mut wakers) = self.wakers.remove(&handle) {
            tracing::trace!(?handle, "notify {}", wakers.len());
            for waker in wakers.drain(..) {
                waker.wake();
            }
        }
        handle
    }

    pub fn try_get(&self, handle: &H) -> Result<&R, MissingResource> {
        self.map
            .get(handle)
            .as_ref()
            .map(|r| &r.value)
            .ok_or_else(|| MissingResource((*handle).into()))
    }

    pub fn poll_get_eventually(&mut self, handle: H, cx: &mut Context<'_>) -> Poll<&R> {
        // cannot use self.get() and self.register_waker() here due to borrow checker.
        if let Some(resource) = self.map.get(&handle).as_ref().map(|r| &r.value) {
            Poll::Ready(resource)
        } else {
            self.wakers
                .entry(handle)
                .or_default()
                .push_back(cx.waker().to_owned());
            Poll::Pending
        }
    }

    pub fn update(&mut self, handle: H, resource: R) -> Result<(), Error> {
        match self.map.entry(handle) {
            hash_map::Entry::Vacant(_) => Err(Error::MissingResource(handle.into())),
            hash_map::Entry::Occupied(mut entry) => {
                entry.get_mut().value = resource;
                Ok(())
            }
        }
    }
}
impl<H, R> ResourceMap<H, R>
where
    H: IsHandle,
    R: Eq + PartialEq,
{
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

    pub fn find(&self, resource: &R) -> Option<H> {
        self.map
            .iter()
            .find_map(|(handle, r)| (r.value == *resource).then_some(*handle))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("missing resource {0:?}")]
pub struct MissingResource(pub ResourceHandle);

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
