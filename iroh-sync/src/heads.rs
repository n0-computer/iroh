//! Author heads

use std::collections::BTreeMap;

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

    /// Can this state offer newer stuff to `other`?
    pub fn has_news_for(&self, other: &Self) -> bool {
        for (author, ts_theirs) in other.iter() {
            match self.heads.get(&author) {
                None => return true,
                Some(ts_ours) => {
                    if ts_theirs > ts_ours {
                        return true;
                    }
                }
            }
        }
        false
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
            .map(|n| (AuthorId::from(&[9 - n as u8; 32]), start + (9 - n as u64)))
            .collect();
        assert_eq!(expected, decoded);
        Ok(())
    }
}
