//! Author heads

use std::{collections::BTreeMap, num::NonZeroU64};

use anyhow::Result;

use crate::AuthorId;

type Timestamp = u64;

/// Timestamps of the latest entry for each author.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct AuthorHeads {
    heads: BTreeMap<AuthorId, Timestamp>,
}

impl AuthorHeads {
    /// Insert a new timestamp.
    pub fn insert(&mut self, author: AuthorId, timestamp: Timestamp) {
        self.heads
            .entry(author)
            .and_modify(|t| *t = (*t).max(timestamp))
            .or_insert(timestamp);
    }

    /// Number of author-timestamp pairs.
    pub fn len(&self) -> usize {
        self.heads.len()
    }

    /// Whether this [`AuthorHeads`] is empty.
    pub fn is_empty(&self) -> bool {
        self.heads.is_empty()
    }

    /// Get the timestamp for an author.
    pub fn get(&self, author: &AuthorId) -> Option<Timestamp> {
        self.heads.get(author).copied()
    }

    /// Can this state offer newer stuff to `other`?
    pub fn has_news_for(&self, other: &Self) -> Option<NonZeroU64> {
        let mut updates = 0;
        for (author, ts_ours) in self.iter() {
            if other
                .get(author)
                .map(|ts_theirs| *ts_ours > ts_theirs)
                .unwrap_or(true)
            {
                updates += 1;
            }
        }
        NonZeroU64::new(updates)
    }

    /// Merge another author head state into this one.
    pub fn merge(&mut self, other: &Self) {
        for (a, t) in other.iter() {
            self.insert(*a, *t);
        }
    }

    /// Create an iterator over the entries in this state.
    pub fn iter(&self) -> std::collections::btree_map::Iter<AuthorId, Timestamp> {
        self.heads.iter()
    }

    /// Encode into a byte array with a limited size.
    ///
    /// Will skip oldest entries if the size limit is reached.
    /// Returns a byte array with a maximum length of `size_limit`.
    pub fn encode(&self, size_limit: Option<usize>) -> Result<Vec<u8>> {
        let mut by_timestamp = BTreeMap::new();
        for (author, ts) in self.iter() {
            by_timestamp.insert(*ts, *author);
        }
        let mut items = Vec::new();
        for (ts, author) in by_timestamp.into_iter().rev() {
            items.push((ts, author));
            if let Some(size_limit) = size_limit {
                if postcard::experimental::serialized_size(&items)? > size_limit {
                    items.pop();
                    break;
                }
            }
        }
        let encoded = postcard::to_stdvec(&items)?;
        debug_assert!(size_limit.map(|s| encoded.len() <= s).unwrap_or(true));
        Ok(encoded)
    }

    /// Decode from byte slice created with [`Self::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let items: Vec<(Timestamp, AuthorId)> = postcard::from_bytes(bytes)?;
        let mut heads = AuthorHeads::default();
        for (ts, author) in items {
            heads.insert(author, ts);
        }
        Ok(heads)
    }
}

impl FromIterator<(AuthorId, Timestamp)> for AuthorHeads {
    fn from_iter<T: IntoIterator<Item = (AuthorId, Timestamp)>>(iter: T) -> Self {
        Self {
            heads: iter.into_iter().collect(),
        }
    }
}

impl FromIterator<(Timestamp, AuthorId)> for AuthorHeads {
    fn from_iter<T: IntoIterator<Item = (Timestamp, AuthorId)>>(iter: T) -> Self {
        Self {
            heads: iter.into_iter().map(|(ts, author)| (author, ts)).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Record;

    use super::*;
    #[test]
    fn author_heads_encode_decode() -> Result<()> {
        let mut heads = AuthorHeads::default();
        let start = Record::empty_current().timestamp();
        for i in 0..10u64 {
            heads.insert(AuthorId::from(&[i as u8; 32]), start + i);
        }
        let encoded = heads.encode(Some(256))?;
        let decoded = AuthorHeads::decode(&encoded)?;
        assert_eq!(decoded.len(), 6);
        let expected: AuthorHeads = (0u64..6)
            .map(|n| (AuthorId::from(&[9 - n as u8; 32]), start + (9 - n)))
            .collect();
        assert_eq!(expected, decoded);
        Ok(())
    }

    #[test]
    fn author_heads_compare() -> Result<()> {
        let a = [
            (AuthorId::from(&[0u8; 32]), 5),
            (AuthorId::from(&[1u8; 32]), 7),
        ];
        let b = [
            (AuthorId::from(&[0u8; 32]), 4),
            (AuthorId::from(&[1u8; 32]), 6),
            (AuthorId::from(&[2u8; 32]), 7),
        ];
        let a: AuthorHeads = a.into_iter().collect();
        let b: AuthorHeads = b.into_iter().collect();
        assert_eq!(a.has_news_for(&b), NonZeroU64::new(2));
        assert_eq!(b.has_news_for(&a), NonZeroU64::new(1));
        Ok(())
    }
}
