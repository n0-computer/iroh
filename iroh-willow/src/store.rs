use std::collections::HashMap;

use iroh_base::hash::Hash;

use crate::proto::{
    wgps::{Area, Fingerprint, RangeEnd, ThreeDRange},
    willow::{AuthorisedEntry, Entry, NamespaceId},
};

pub trait Store {
    fn range_fingerprint(
        &mut self,
        namespace: NamespaceId,
        range: &ThreeDRange,
    ) -> anyhow::Result<Fingerprint>;

    fn split_range(
        &mut self,
        namespace: NamespaceId,
        range: &ThreeDRange,
    ) -> anyhow::Result<RangeSplit>;

    fn get_entries<'a>(
        &'a mut self,
        namespace: NamespaceId,
        range: &ThreeDRange,
    ) -> impl Iterator<Item = anyhow::Result<Entry>> + 'a {
        self.get_entries_with_authorisation(namespace, range)
            .map(|e| e.map(|e| e.into_entry()))
    }

    fn get_entries_with_authorisation<'a>(
        &'a mut self,
        namespace: NamespaceId,
        range: &ThreeDRange,
    ) -> impl Iterator<Item = anyhow::Result<AuthorisedEntry>> + 'a;

    fn ingest_entry(&mut self, entry: &AuthorisedEntry) -> anyhow::Result<()>;
}

#[derive(Debug, Default)]
pub struct MemoryStore {
    entries: HashMap<NamespaceId, Vec<AuthorisedEntry>>,
}

impl Store for MemoryStore {
    fn range_fingerprint(
        &mut self,
        namespace: NamespaceId,
        range: &ThreeDRange,
    ) -> anyhow::Result<Fingerprint> {
        let mut fingerprint = Fingerprint::default();
        for entry in self.get_entries(namespace, range) {
            let entry = entry?;
            fingerprint.add_entry(&entry);
        }
        Ok(fingerprint)
    }

    fn split_range(
        &mut self,
        namespace: NamespaceId,
        range: &ThreeDRange,
    ) -> anyhow::Result<RangeSplit> {
        let count = self.get_entries(namespace, range).count();
        let split_if_more_than = 2;
        let res = if count > split_if_more_than {
            let mut entries: Vec<_> = self
                .get_entries(namespace, range)
                .filter_map(|e| e.ok())
                .collect();
            let pivot_index = count / 2;
            let right = entries.split_off(pivot_index);
            let left = entries;

            let pivot = right.first().unwrap();
            let mut range_left = range.clone();
            range_left.paths.end = RangeEnd::Closed(pivot.path.clone());
            range_left.times.end = RangeEnd::Closed(pivot.timestamp);
            range_left.subspaces.end = RangeEnd::Closed(pivot.subspace_id);

            let mut range_right = range.clone();
            range_right.paths.start = pivot.path.clone();
            range_right.times.start = pivot.timestamp;
            range_right.subspaces.start = pivot.subspace_id;

            let left_part = if left.len() > split_if_more_than {
                let fp = Fingerprint::from_entries(left.iter());
                RangeSplitPart::SendFingerprint(range_left, fp)
            } else {
                RangeSplitPart::SendEntries(range_left, left.len() as u64)
            };

            let right_part = if left.len() > split_if_more_than {
                let fp = Fingerprint::from_entries(right.iter());
                RangeSplitPart::SendFingerprint(range_right, fp)
            } else {
                RangeSplitPart::SendEntries(range_right, right.len() as u64)
            };

            RangeSplit::SendSplit([left_part, right_part])
        } else {
            RangeSplit::SendEntries(range.clone(), count as u64)
        };
        Ok(res)
    }

    fn get_entries_with_authorisation<'a>(
        &'a mut self,
        namespace: NamespaceId,
        range: &ThreeDRange,
    ) -> impl Iterator<Item = anyhow::Result<AuthorisedEntry>> + 'a {
        self.entries
            .get(&namespace)
            .into_iter()
            .flatten()
            .filter(|entry| range.includes_entry(entry.entry()))
            .map(|e| Result::<_, anyhow::Error>::Ok(e.clone()))
            .collect::<Vec<_>>()
            .into_iter()
    }

    fn ingest_entry(&mut self, entry: &AuthorisedEntry) -> anyhow::Result<()> {
        let entries = self.entries.entry(entry.namespace_id()).or_default();
        let new = entry.entry();
        let mut to_remove = vec![];
        for (i, other) in entries.iter().enumerate() {
            let old = other.entry();
            if old.subspace_id == new.subspace_id && old.path.is_prefix_of(&new.path) && old >= new
            {
                // we cannot insert the entry, a newer entry exists
                return Ok(());
            }
            if new.subspace_id == old.subspace_id && new.path.is_prefix_of(&old.path) && new > old {
                to_remove.push(i);
            }
        }
        for i in to_remove {
            entries.remove(i);
        }

        entries.push(entry.clone());
        Ok(())
    }
}

#[derive(Debug)]
pub enum RangeSplit {
    SendEntries(ThreeDRange, u64),
    SendSplit([RangeSplitPart; 2]),
}

impl IntoIterator for RangeSplit {
    type IntoIter = RangeSplitIterator;
    type Item = RangeSplitPart;
    fn into_iter(self) -> Self::IntoIter {
        RangeSplitIterator(match self {
            RangeSplit::SendEntries(range, len) => {
                [Some(RangeSplitPart::SendEntries(range, len)), None]
            }
            RangeSplit::SendSplit(parts) => parts.map(Option::Some),
        })
    }
}

#[derive(Debug)]
pub struct RangeSplitIterator([Option<RangeSplitPart>; 2]);

impl Iterator for RangeSplitIterator {
    type Item = RangeSplitPart;
    fn next(&mut self) -> Option<Self::Item> {
        self.0.iter_mut().filter_map(Option::take).next()
    }
}

#[derive(Debug)]
pub enum RangeSplitPart {
    SendEntries(ThreeDRange, u64),
    SendFingerprint(ThreeDRange, Fingerprint),
}
