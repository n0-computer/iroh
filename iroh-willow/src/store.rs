use std::collections::HashMap;

use anyhow::Result;

use crate::proto::{
    grouping::{Range, RangeEnd, ThreeDRange},
    wgps::Fingerprint,
    willow::{AuthorisedEntry, Entry, NamespaceId},
};

#[derive(Debug, Clone, Copy)]
pub struct SyncConfig {
    /// Up to how many values to send immediately, before sending only a fingerprint.
    pub max_set_size: usize,
    /// `k` in the protocol, how many splits to generate. at least 2
    pub split_factor: usize,
}

impl Default for SyncConfig {
    fn default() -> Self {
        SyncConfig {
            max_set_size: 1,
            split_factor: 2,
        }
    }
}

pub trait Store: Send + 'static {
    fn range_fingerprint(
        &mut self,
        namespace: NamespaceId,
        range: &ThreeDRange,
    ) -> Result<Fingerprint>;

    fn split_range(
        &mut self,
        namespace: NamespaceId,
        range: &ThreeDRange,
        config: &SyncConfig,
    ) -> Result<impl Iterator<Item = Result<RangeSplit>>>;

    fn count_range(&mut self, namespace: NamespaceId, range: &ThreeDRange) -> Result<u64>;

    fn get_entries_with_authorisation<'a>(
        &'a mut self,
        namespace: NamespaceId,
        range: &ThreeDRange,
    ) -> impl Iterator<Item = Result<AuthorisedEntry>> + 'a;

    fn ingest_entry(&mut self, entry: &AuthorisedEntry) -> Result<()>;

    fn get_entries<'a>(
        &'a mut self,
        namespace: NamespaceId,
        range: &ThreeDRange,
    ) -> impl Iterator<Item = Result<Entry>> + 'a {
        self.get_entries_with_authorisation(namespace, range)
            .map(|e| e.map(|e| e.into_entry()))
    }
}

/// A very inefficient in-memory store, for testing purposes only
#[derive(Debug, Default)]
pub struct MemoryStore {
    entries: HashMap<NamespaceId, Vec<AuthorisedEntry>>,
}

impl Store for MemoryStore {
    fn range_fingerprint(
        &mut self,
        namespace: NamespaceId,
        range: &ThreeDRange,
    ) -> Result<Fingerprint> {
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
        config: &SyncConfig,
    ) -> Result<impl Iterator<Item = Result<RangeSplit>>> {
        let count = self.get_entries(namespace, range).count();
        if count <= config.max_set_size {
            return Ok(
                vec![Ok((range.clone(), SplitAction::SendEntries(count as u64)))].into_iter(),
            );
        }
        let mut entries: Vec<Entry> = self
            .get_entries(namespace, range)
            .filter_map(|e| e.ok())
            .collect();

        entries.sort_by(|e1, e2| e1.as_set_sort_tuple().cmp(&e2.as_set_sort_tuple()));

        let split_index = count / 2;
        let mid = entries.get(split_index).expect("not empty");
        let mut ranges = vec![];
        // split in two halves by subspace
        if mid.subspace_id != range.subspaces.start {
            ranges.push(ThreeDRange::new(
                Range::new(range.subspaces.start, RangeEnd::Closed(mid.subspace_id)),
                range.paths.clone(),
                range.times.clone(),
            ));
            ranges.push(ThreeDRange::new(
                Range::new(mid.subspace_id, range.subspaces.end),
                range.paths.clone(),
                range.times.clone(),
            ));
        }
        // split by path
        else if mid.path != range.paths.start {
            ranges.push(ThreeDRange::new(
                range.subspaces.clone(),
                Range::new(
                    range.paths.start.clone(),
                    RangeEnd::Closed(mid.path.clone()),
                ),
                range.times.clone(),
            ));
            ranges.push(ThreeDRange::new(
                range.subspaces.clone(),
                Range::new(mid.path.clone(), range.paths.end.clone()),
                range.times.clone(),
            ));
        // split by time
        } else {
            ranges.push(ThreeDRange::new(
                range.subspaces.clone(),
                range.paths.clone(),
                Range::new(range.times.start, RangeEnd::Closed(mid.timestamp)),
            ));
            ranges.push(ThreeDRange::new(
                range.subspaces.clone(),
                range.paths.clone(),
                Range::new(mid.timestamp, range.times.end),
            ));
        }
        let mut out = vec![];
        for range in ranges {
            let fingerprint = self.range_fingerprint(namespace, &range)?;
            out.push(Ok((range, SplitAction::SendFingerprint(fingerprint))));
        }
        Ok(out.into_iter())
    }

    fn count_range(&mut self, namespace: NamespaceId, range: &ThreeDRange) -> Result<u64> {
        Ok(self.get_entries(namespace, range).count() as u64)
    }

    fn get_entries_with_authorisation<'a>(
        &'a mut self,
        namespace: NamespaceId,
        range: &ThreeDRange,
    ) -> impl Iterator<Item = Result<AuthorisedEntry>> + 'a {
        self.entries
            .get(&namespace)
            .into_iter()
            .flatten()
            .filter(|entry| range.includes_entry(entry.entry()))
            .map(|e| Result::<_, anyhow::Error>::Ok(e.clone()))
            .collect::<Vec<_>>()
            .into_iter()
    }

    fn ingest_entry(&mut self, entry: &AuthorisedEntry) -> Result<()> {
        let entries = self.entries.entry(entry.namespace_id()).or_default();
        let new = entry.entry();
        let mut to_remove = vec![];
        for (i, existing) in entries.iter().enumerate() {
            let existing = existing.entry();
            if existing.subspace_id == new.subspace_id
                && existing.path.is_prefix_of(&new.path)
                && existing.is_newer_than(new)
            {
                // we cannot insert the entry, a newer entry exists
                return Ok(());
            }
            if new.subspace_id == existing.subspace_id
                && new.path.is_prefix_of(&existing.path)
                && new.is_newer_than(existing)
            {
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

pub type RangeSplit = (ThreeDRange, SplitAction);

#[derive(Debug)]
pub enum SplitAction {
    SendFingerprint(Fingerprint),
    SendEntries(u64),
}
