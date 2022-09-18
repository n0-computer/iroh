use std::{ops::Deref, sync::Arc};

use ahash::AHashMap;
use cid::Cid;

use crate::message::{Priority, WantType};

/// A raw list of wanted blocks and their priorities
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Wantlist {
    set: AHashMap<Cid, Entry>,
    /// Sorted version of the entires in `set`.
    cached: Vec<Entry>,
}

impl Wantlist {
    pub fn len(&self) -> usize {
        self.set.len()
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    pub fn clear(&mut self) {
        self.set.clear();
        self.cached.clear();
    }

    /// Adds an entry to thew wantlist, if not already present.
    pub fn add(&mut self, cid: Cid, priority: Priority, want_type: WantType) -> bool {
        if let Some(entry) = self.set.get(&cid) {
            // Adding want-have should not override want-block
            if entry.want_type == WantType::Block || want_type == WantType::Have {
                return false;
            }
        }

        self.cached.clear();
        self.set.insert(cid, Entry::new(cid, priority, want_type));

        true
    }

    /// Removes the given Cid from the wantlist.
    pub fn remove(&mut self, cid: &Cid) -> Option<Entry> {
        self.cached.clear();
        self.set.remove(cid)
    }

    /// Returns the entry if present, otherwise `None`.
    pub fn get(&self, cid: &Cid) -> Option<&Entry> {
        self.set.get(cid)
    }

    /// Removes the given Cid from the wantlist, respecting the type.
    pub fn remove_type(&mut self, cid: &Cid, want_type: WantType) -> Option<Entry> {
        if !self.set.contains_key(cid) {
            return None;
        }

        if let Some(entry) = self.set.get(cid) {
            if entry.want_type == WantType::Block && want_type == WantType::Have {
                return None;
            }
        }

        self.cached.clear();
        self.set.remove(cid)
    }

    /// Returns a list of the entries, sorted descending by priority.
    pub fn entries(&mut self) -> impl Iterator<Item = Entry> + '_ {
        if self.cached.is_empty() {
            for v in self.set.values() {
                self.cached.push(v.clone());
            }
            self.cached.sort_by_cached_key(|e| e.priority);
            self.cached.reverse();
        }

        self.cached.iter().map(|c| c.clone())
    }

    /// Merges the second wantlist into thise one.
    pub fn extend(&mut self, other: &Self) {
        self.cached.clear();

        for entry in other.set.values() {
            self.add(entry.cid, entry.priority, entry.want_type);
        }
    }
}

/// An entry in a wantlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry(Arc<InnerEntry>);

impl Deref for Entry {
    type Target = InnerEntry;
    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerEntry {
    pub cid: Cid,
    pub priority: Priority,
    pub want_type: WantType,
}

impl Entry {
    pub fn new(cid: Cid, priority: Priority, want_type: WantType) -> Self {
        Entry(Arc::new(InnerEntry {
            cid,
            priority,
            want_type,
        }))
    }
    pub fn new_ref(cid: Cid, priority: Priority) -> Self {
        Entry::new(cid, priority, WantType::Block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_test_cids() -> Vec<Cid> {
        let cids = [
            "QmQL8LqkEgYXaDHdNYCG2mmpow7Sp8Z8Kt3QS688vyBeC7",
            "QmcBDsdjgSXU7BP4A4V8LJCXENE5xVwnhrhRGVTJr9YCVj",
            "QmQakgd2wDxc3uUF4orGdEm28zUT9Mmimp5pyPG2SFS9Gj",
        ];

        cids.into_iter()
            .map(|c| Cid::try_from(c).unwrap())
            .collect()
    }

    #[test]
    fn test_basic_wantlist() {
        let test_cids = get_test_cids();
        let mut wl = Wantlist::default();

        assert!(wl.add(test_cids[0], 5, WantType::Block));
        assert_eq!(wl.get(&test_cids[0]).unwrap().cid, test_cids[0]);

        assert!(wl.add(test_cids[1], 4, WantType::Block));
        assert_eq!(wl.get(&test_cids[0]).unwrap().cid, test_cids[0]);
        assert_eq!(wl.get(&test_cids[1]).unwrap().cid, test_cids[1]);

        assert_eq!(wl.len(), 2);

        assert!(!wl.add(test_cids[1], 4, WantType::Block));
        assert_eq!(wl.len(), 2);

        assert!(wl.remove_type(&test_cids[0], WantType::Block).is_some());
        assert_eq!(wl.get(&test_cids[1]).unwrap().cid, test_cids[1]);
        assert!(wl.get(&test_cids[0]).is_none());
    }

    #[test]
    fn test_add_have_then_block() {
        let test_cids = get_test_cids();
        let mut wl = Wantlist::default();

        assert!(wl.add(test_cids[0], 5, WantType::Have));
        assert!(wl.add(test_cids[0], 5, WantType::Block));

        assert_eq!(wl.len(), 1);
        let entry = wl.get(&test_cids[0]).unwrap();
        assert_eq!(entry.want_type, WantType::Block);
    }

    #[test]
    fn test_add_block_then_have() {
        let test_cids = get_test_cids();
        let mut wl = Wantlist::default();

        assert!(wl.add(test_cids[0], 5, WantType::Block));
        assert!(!wl.add(test_cids[0], 5, WantType::Have));

        assert_eq!(wl.len(), 1);
        let entry = wl.get(&test_cids[0]).unwrap();
        assert_eq!(entry.want_type, WantType::Block);
    }

    #[test]
    fn test_add_have_then_remove_block() {
        let test_cids = get_test_cids();
        let mut wl = Wantlist::default();

        assert!(wl.add(test_cids[0], 5, WantType::Have));
        assert!(wl.remove_type(&test_cids[0], WantType::Block).is_some());

        assert!(wl.is_empty());
    }

    #[test]
    fn test_add_block_then_remove_have() {
        let test_cids = get_test_cids();
        let mut wl = Wantlist::default();

        assert!(wl.add(test_cids[0], 5, WantType::Block));
        assert!(wl.remove_type(&test_cids[0], WantType::Have).is_none());

        assert_eq!(wl.len(), 1);
        assert_eq!(wl.get(&test_cids[0]).unwrap().want_type, WantType::Block);
    }

    #[test]
    fn test_add_have_then_remove_any() {
        let test_cids = get_test_cids();
        let mut wl = Wantlist::default();

        assert!(wl.add(test_cids[0], 5, WantType::Have));
        assert!(wl.remove(&test_cids[0]).is_some());

        assert!(wl.is_empty());
    }

    #[test]
    fn test_add_block_then_remove_any() {
        let test_cids = get_test_cids();
        let mut wl = Wantlist::default();

        assert!(wl.add(test_cids[0], 5, WantType::Block));
        assert!(wl.remove(&test_cids[0]).is_some());

        assert!(wl.is_empty());
    }

    #[test]
    fn test_extend() {
        let test_cids = get_test_cids();
        let mut wl = Wantlist::default();

        assert!(wl.add(test_cids[0], 5, WantType::Block));
        assert!(wl.add(test_cids[1], 4, WantType::Have));
        assert!(wl.add(test_cids[2], 3, WantType::Have));

        let mut wl2 = Wantlist::default();
        assert!(wl2.add(test_cids[0], 2, WantType::Have));
        assert!(wl2.add(test_cids[1], 1, WantType::Block));

        wl.extend(&wl2);

        let entry = wl.get(&test_cids[0]).unwrap();
        assert_eq!(entry.priority, 5);
        assert_eq!(entry.want_type, WantType::Block);

        let entry = wl.get(&test_cids[1]).unwrap();
        assert_eq!(entry.priority, 1);
        assert_eq!(entry.want_type, WantType::Block);

        let entry = wl.get(&test_cids[2]).unwrap();
        assert_eq!(entry.priority, 3);
        assert_eq!(entry.want_type, WantType::Have);
    }

    #[test]
    fn test_sort_entries() {
        let test_cids = get_test_cids();
        let mut wl = Wantlist::default();

        assert!(wl.add(test_cids[0], 3, WantType::Block));
        assert!(wl.add(test_cids[1], 5, WantType::Have));
        assert!(wl.add(test_cids[2], 4, WantType::Have));

        for (i, entry) in wl.entries().enumerate() {
            if i == 0 {
                assert_eq!(entry.cid, test_cids[1]);
            } else if i == 1 {
                assert_eq!(entry.cid, test_cids[2]);
            } else if i == 2 {
                assert_eq!(entry.cid, test_cids[0]);
            }
        }
    }

    #[test]
    fn test_cache() {
        let test_cids = get_test_cids();
        let mut wl = Wantlist::default();

        assert!(wl.add(test_cids[0], 3, WantType::Block));
        assert_eq!(wl.entries().count(), 1);

        assert!(wl.add(test_cids[1], 3, WantType::Block));
        assert_eq!(wl.entries().count(), 2);

        assert!(wl.remove(&test_cids[1]).is_some());
        assert_eq!(wl.entries().count(), 1);
    }
}
