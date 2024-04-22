use std::collections::HashMap;

use crate::proto::{
    wgps::{Area, Fingerprint, ThreeDRange},
    willow::{AuthorisedEntry, NamespaceId},
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
        let _ = namespace;
        let _ = range;
        todo!()
    }

    fn split_range(
        &mut self,
        namespace: NamespaceId,
        range: &ThreeDRange,
    ) -> anyhow::Result<RangeSplit> {
        let _ = namespace;
        let _ = range;
        todo!()
    }

    fn get_entries_with_authorisation<'a>(
        &'a mut self,
        namespace: NamespaceId,
        range: &ThreeDRange,
    ) -> impl Iterator<Item = anyhow::Result<AuthorisedEntry>> + 'a {
        let _ = namespace;
        let _ = range;
        None.into_iter()
    }

    fn ingest_entry(&mut self, entry: &AuthorisedEntry) -> anyhow::Result<()> {
        let _ = entry;
        todo!()
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
