use std::ops::Bound;

use bytes::Bytes;

use crate::{store::KeyFilter, AuthorId, NamespaceId};

use super::{RecordsByKeyId, RecordsByKeyIdOwned, RecordsId, RecordsIdOwned};

/// Bounds on the recors table.
///
/// Supports bounds by author, key
pub struct RecordsBounds((Bound<RecordsIdOwned>, Bound<RecordsIdOwned>));

impl RecordsBounds {
    pub fn bounded(ns: NamespaceId, author: AuthorId, key_matcher: KeyFilter) -> Self {
        let key_is_exact = matches!(key_matcher, KeyFilter::Exact(_));
        let key = match key_matcher {
            KeyFilter::Any => Bytes::new(),
            KeyFilter::Exact(key) => key,
            KeyFilter::Prefix(prefix) => prefix,
        };
        let author = author.to_bytes();
        let ns = ns.to_bytes();
        let mut author_end = author;
        let mut ns_end = ns;
        let mut key_end = key.to_vec();

        let start = (ns, author, key);

        let end = if key_is_exact {
            Bound::Included(start.clone())
        } else if increment_by_one(&mut key_end) {
            Bound::Excluded((ns, author_end, key_end.into()))
        } else if increment_by_one(&mut author_end) {
            Bound::Excluded((ns, author_end, Bytes::new()))
        } else if increment_by_one(&mut ns_end) {
            Bound::Excluded((ns_end, [0u8; 32], Bytes::new()))
        } else {
            Bound::Unbounded
        };

        Self((Bound::Included(start), end))
    }

    pub fn author_prefix(ns: NamespaceId, author: AuthorId, prefix: Bytes) -> Self {
        RecordsBounds::bounded(ns, author, KeyFilter::Prefix(prefix))
    }

    pub fn namespace(ns: NamespaceId) -> Self {
        let start = Bound::Included((ns.to_bytes(), [0u8; 32], Bytes::new()));
        let end = namespace_end(&ns);
        Self((start, end))
    }

    pub fn from_start(ns: &NamespaceId, end: Bound<RecordsIdOwned>) -> Self {
        Self((namespace_start(ns), end))
    }

    pub fn to_end(ns: &NamespaceId, start: Bound<RecordsIdOwned>) -> Self {
        Self((start, namespace_end(ns)))
    }

    pub fn with_bounds(start: Bound<RecordsIdOwned>, end: Bound<RecordsIdOwned>) -> Self {
        Self((start, end))
    }

    pub fn as_ref(&self) -> (Bound<RecordsId>, Bound<RecordsId>) {
        map_bounds(&self.0, records_id_ref)
    }
}

/// Bounds for the by-key index table.
///
/// Supports bounds by key.
pub struct ByKeyBounds((Bound<RecordsByKeyIdOwned>, Bound<RecordsByKeyIdOwned>));
impl ByKeyBounds {
    pub fn new(ns: NamespaceId, matcher: &KeyFilter) -> Self {
        let ns = ns.as_bytes();
        let bounds = match matcher {
            KeyFilter::Any => {
                let start = (*ns, Bytes::new(), [0u8; 32]);
                let mut ns_end = *ns;
                let end = match increment_by_one(&mut ns_end) {
                    true => Bound::Excluded((ns_end, Bytes::new(), [0u8; 32])),
                    false => Bound::Unbounded,
                };
                (Bound::Included(start), end)
            }
            KeyFilter::Exact(key) => {
                let start = (*ns, key.clone(), [0u8; 32]);
                let end = (*ns, key.clone(), [255u8; 32]);
                (Bound::Included(start), Bound::Included(end))
            }
            KeyFilter::Prefix(ref prefix) => {
                let start = (*ns, prefix.clone(), [0u8; 32]);
                let mut key_end = prefix.to_vec();
                let mut ns_end = *ns;
                let end = if increment_by_one(&mut key_end) {
                    Bound::Excluded((*ns, key_end.into(), [0u8; 32]))
                } else if increment_by_one(&mut ns_end) {
                    Bound::Excluded((ns_end, Bytes::new(), [0u8; 32]))
                } else {
                    Bound::Unbounded
                };
                (Bound::Included(start), end)
            }
        };
        Self(bounds)
    }

    pub fn namespace(ns: NamespaceId) -> Self {
        Self::new(ns, &KeyFilter::Any)
    }

    pub fn as_ref(&self) -> (Bound<RecordsByKeyId>, Bound<RecordsByKeyId>) {
        map_bounds(&self.0, records_by_key_id_ref)
    }
}

/// Increment a byte string by one, by incrementing the last byte that is not 255 by one.
///
/// Returns false if all bytes are 255.
fn increment_by_one(value: &mut [u8]) -> bool {
    for char in value.iter_mut().rev() {
        if *char != 255 {
            *char += 1;
            return true;
        } else {
            *char = 0;
        }
    }
    false
}

fn map_bound<'a, T, U: 'a>(bound: &'a Bound<T>, f: impl Fn(&'a T) -> U) -> Bound<U> {
    match bound {
        Bound::Unbounded => Bound::Unbounded,
        Bound::Included(t) => Bound::Included(f(t)),
        Bound::Excluded(t) => Bound::Excluded(f(t)),
    }
}

fn map_bounds<'a, T, U: 'a>(
    bounds: &'a (Bound<T>, Bound<T>),
    f: impl Fn(&'a T) -> U,
) -> (Bound<U>, Bound<U>) {
    (map_bound(&bounds.0, &f), map_bound(&bounds.1, f))
}

fn records_by_key_id_ref(id: &RecordsByKeyIdOwned) -> RecordsByKeyId {
    (&id.0, &id.1[..], &id.2)
}

fn records_id_ref(id: &RecordsIdOwned) -> RecordsId {
    (&id.0, &id.1, &id.2[..])
}

fn namespace_start(namespace: &NamespaceId) -> Bound<RecordsIdOwned> {
    Bound::Included((namespace.to_bytes(), [0u8; 32], Bytes::new()))
}

fn namespace_end(namespace: &NamespaceId) -> Bound<RecordsIdOwned> {
    let mut ns_end = *(namespace.as_bytes());
    if increment_by_one(&mut ns_end) {
        Bound::Excluded((ns_end, [0u8; 32], Bytes::new()))
    } else {
        Bound::Unbounded
    }
}
