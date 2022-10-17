use std::collections::VecDeque;

use ahash::AHashSet;
use cid::Cid;

#[derive(Default, Debug)]
pub struct CidQueue {
    elements: VecDeque<Cid>,
    set: AHashSet<Cid>,
}

impl CidQueue {
    pub fn pop(&mut self) -> Option<Cid> {
        while let Some(el) = self.elements.pop_front() {
            if self.set.contains(&el) {
                return Some(el);
            }
        }

        None
    }

    #[allow(dead_code)]
    pub fn cids(&mut self) -> Vec<Cid> {
        // Lazily deletes cids removed from the set.
        self.elements.retain(|el| self.set.contains(el));

        self.elements.iter().copied().collect()
    }

    pub fn push(&mut self, cid: Cid) {
        if self.set.insert(cid) {
            self.elements.push_back(cid);
        }
    }

    pub fn remove(&mut self, cid: &Cid) {
        self.set.remove(cid);
    }

    pub fn has(&self, cid: &Cid) -> bool {
        self.set.contains(cid)
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }
}
