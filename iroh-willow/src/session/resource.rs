use std::collections::HashMap;

use crate::proto::wgps::{
    AreaOfInterestHandle, CapabilityHandle, Handle, ReadCapability, SetupBindAreaOfInterest,
    StaticToken, StaticTokenHandle,
};

use super::Error;

#[derive(Debug, Default)]
pub struct ScopedResources {
    pub capabilities: ResourceMap<CapabilityHandle, ReadCapability>,
    pub areas_of_interest: ResourceMap<AreaOfInterestHandle, SetupBindAreaOfInterest>,
    pub static_tokens: ResourceMap<StaticTokenHandle, StaticToken>,
}

#[derive(Debug)]
pub struct ResourceMap<H, R> {
    next_handle: u64,
    map: HashMap<H, Resource<R>>,
}

impl<H, R> Default for ResourceMap<H, R> {
    fn default() -> Self {
        Self {
            next_handle: 0,
            map: Default::default(),
        }
    }
}

impl<H, R> ResourceMap<H, R>
where
    H: Handle,
    R: Eq + PartialEq,
{
    pub fn bind(&mut self, resource: R) -> H {
        let handle: H = self.next_handle.into();
        self.next_handle += 1;
        let resource = Resource::new(resource);
        self.map.insert(handle, resource);
        handle
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
            .ok_or(Error::MissingResource)
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
