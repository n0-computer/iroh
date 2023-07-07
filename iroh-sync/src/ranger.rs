//! Implementation of Set Reconcilliation based on
//! "Range-Based Set Reconciliation" by Aljoscha Meyer.
//!

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

/// Stores a range.
///
/// There are three possibilities
/// - x, x: All elements in a set, denoted with
/// - [x, y): x < y: Includes x, but not y
/// - S \ [y, x) y < x: Includes x, but not y.
/// This means that ranges are "wrap around" conceptually.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
pub struct Range<K> {
    x: K,
    y: K,
}

impl<K> Range<K> {
    pub fn x(&self) -> &K {
        &self.x
    }

    pub fn y(&self) -> &K {
        &self.y
    }

    pub fn new(x: K, y: K) -> Self {
        Range { x, y }
    }

    pub fn map<X>(self, f: impl FnOnce(K, K) -> (X, X)) -> Range<X> {
        let (x, y) = f(self.x, self.y);
        Range { x, y }
    }
}

impl<K> From<(K, K)> for Range<K> {
    fn from((x, y): (K, K)) -> Self {
        Range { x, y }
    }
}

pub trait RangeKey: Sized + Ord + Debug {
    /// Is this key inside the range?
    fn contains(&self, range: &Range<Self>) -> bool {
        contains(self, range)
    }
}

/// Default implementation of `contains` for `Ord` types.
pub fn contains<T: Ord>(t: &T, range: &Range<T>) -> bool {
    match range.x().cmp(range.y()) {
        Ordering::Equal => true,
        Ordering::Less => range.x() <= t && t < range.y(),
        Ordering::Greater => range.x() <= t || t < range.y(),
    }
}

impl RangeKey for &str {}
impl RangeKey for &[u8] {}

#[derive(Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct Fingerprint(pub [u8; 32]);

impl Debug for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Fp({})", blake3::Hash::from(self.0).to_hex())
    }
}

impl Fingerprint {
    /// The fingerprint of the empty set
    pub fn empty() -> Self {
        Fingerprint::new(&[][..])
    }

    pub fn new<T: AsFingerprint>(val: T) -> Self {
        val.as_fingerprint()
    }
}

pub trait AsFingerprint {
    fn as_fingerprint(&self) -> Fingerprint;
}

impl<T: AsRef<[u8]>> AsFingerprint for T {
    fn as_fingerprint(&self) -> Fingerprint {
        Fingerprint(blake3::hash(self.as_ref()).into())
    }
}

impl std::ops::BitXorAssign for Fingerprint {
    fn bitxor_assign(&mut self, rhs: Self) {
        for (a, b) in self.0.iter_mut().zip(rhs.0.iter()) {
            *a ^= b;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RangeFingerprint<K> {
    #[serde(bound(
        serialize = "Range<K>: Serialize",
        deserialize = "Range<K>: Deserialize<'de>"
    ))]
    pub range: Range<K>,
    /// The fingerprint of `range`.
    pub fingerprint: Fingerprint,
}

/// Transfers items inside a range to the other participant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RangeItem<K, V> {
    /// The range out of which the elements are.
    #[serde(bound(
        serialize = "Range<K>: Serialize",
        deserialize = "Range<K>: Deserialize<'de>"
    ))]
    pub range: Range<K>,
    #[serde(bound(
        serialize = "K: Serialize, V: Serialize",
        deserialize = "K: Deserialize<'de>, V: Deserialize<'de>"
    ))]
    pub values: Vec<(K, V)>,
    /// If false, requests to send local items in the range.
    /// Otherwise not.
    pub have_local: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MessagePart<K, V> {
    #[serde(bound(
        serialize = "RangeFingerprint<K>: Serialize",
        deserialize = "RangeFingerprint<K>: Deserialize<'de>"
    ))]
    RangeFingerprint(RangeFingerprint<K>),
    #[serde(bound(
        serialize = "RangeItem<K, V>: Serialize",
        deserialize = "RangeItem<K, V>: Deserialize<'de>"
    ))]
    RangeItem(RangeItem<K, V>),
}

impl<K, V> MessagePart<K, V> {
    pub fn is_range_fingerprint(&self) -> bool {
        matches!(self, MessagePart::RangeFingerprint(_))
    }

    pub fn is_range_item(&self) -> bool {
        matches!(self, MessagePart::RangeItem(_))
    }

    pub fn values(&self) -> Option<&[(K, V)]> {
        match self {
            MessagePart::RangeFingerprint(_) => None,
            MessagePart::RangeItem(RangeItem { values, .. }) => Some(values),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message<K, V> {
    #[serde(bound(
        serialize = "MessagePart<K, V>: Serialize",
        deserialize = "MessagePart<K, V>: Deserialize<'de>"
    ))]
    parts: Vec<MessagePart<K, V>>,
}

impl<K, V> Message<K, V>
where
    K: RangeKey + Clone + Default + AsFingerprint,
{
    /// Construct the initial message.
    fn init<S: Store<K, V>>(store: &S, limit: Option<&Range<K>>) -> Self {
        let x = store.get_first();
        let range = Range::new(x.clone(), x);
        let fingerprint = store.get_fingerprint(&range, limit);
        let part = MessagePart::RangeFingerprint(RangeFingerprint { range, fingerprint });
        Message { parts: vec![part] }
    }

    pub fn parts(&self) -> &[MessagePart<K, V>] {
        &self.parts
    }
}

pub trait Store<K, V>: Sized + Default
where
    K: RangeKey + Clone + Default + AsFingerprint,
{
    /// Get a the first key (or the default if none is available).
    fn get_first(&self) -> K;
    fn get(&self, key: &K) -> Option<&V>;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool;
    /// Calculate the fingerprint of the given range.
    fn get_fingerprint(&self, range: &Range<K>, limit: Option<&Range<K>>) -> Fingerprint;

    /// Insert the given key value pair.
    fn put(&mut self, k: K, v: V);

    type RangeIterator<'a>: Iterator<Item = (&'a K, &'a V)>
    where
        Self: 'a,
        K: 'a,
        V: 'a;

    /// Returns all items in the given range
    fn get_range<'a>(&'a self, range: Range<K>, limit: Option<Range<K>>)
        -> Self::RangeIterator<'a>;
    fn remove(&mut self, key: &K) -> Option<V>;

    type AllIterator<'a>: Iterator<Item = (&'a K, &'a V)>
    where
        Self: 'a,
        K: 'a,
        V: 'a;
    fn all(&self) -> Self::AllIterator<'_>;
}

#[derive(Debug)]
pub struct SimpleStore<K, V> {
    data: BTreeMap<K, V>,
}

impl<K, V> Default for SimpleStore<K, V> {
    fn default() -> Self {
        SimpleStore {
            data: BTreeMap::default(),
        }
    }
}

impl<K, V> Store<K, V> for SimpleStore<K, V>
where
    K: RangeKey + Clone + Default + AsFingerprint,
{
    fn get_first(&self) -> K {
        if let Some((k, _)) = self.data.first_key_value() {
            k.clone()
        } else {
            Default::default()
        }
    }

    fn get(&self, key: &K) -> Option<&V> {
        self.data.get(key)
    }

    fn len(&self) -> usize {
        self.data.len()
    }

    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Calculate the fingerprint of the given range.
    fn get_fingerprint(&self, range: &Range<K>, limit: Option<&Range<K>>) -> Fingerprint {
        let elements = self.get_range(range.clone(), limit.cloned());
        let mut fp = Fingerprint::empty();
        for el in elements {
            fp ^= el.0.as_fingerprint();
        }

        fp
    }

    /// Insert the given key value pair.
    fn put(&mut self, k: K, v: V) {
        self.data.insert(k, v);
    }

    type RangeIterator<'a> = SimpleRangeIterator<'a, K, V>
        where K: 'a, V: 'a;
    /// Returns all items in the given range
    fn get_range<'a>(
        &'a self,
        range: Range<K>,
        limit: Option<Range<K>>,
    ) -> Self::RangeIterator<'a> {
        // TODO: this is not very efficient, optimize depending on data structure
        let iter = self.data.iter();

        SimpleRangeIterator { iter, range, limit }
    }

    fn remove(&mut self, key: &K) -> Option<V> {
        self.data.remove(key)
    }

    type AllIterator<'a> = std::collections::btree_map::Iter<'a, K, V>
    where K: 'a,
          V: 'a;

    fn all(&self) -> Self::AllIterator<'_> {
        self.data.iter()
    }
}

#[derive(Debug)]
pub struct SimpleRangeIterator<'a, K: 'a, V: 'a> {
    iter: std::collections::btree_map::Iter<'a, K, V>,
    range: Range<K>,
    limit: Option<Range<K>>,
}

impl<'a, K, V> Iterator for SimpleRangeIterator<'a, K, V>
where
    K: RangeKey,
{
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        let mut next = self.iter.next()?;

        let filter = |x: &K| {
            let r = x.contains(&self.range);
            if let Some(ref limit) = self.limit {
                r && x.contains(limit)
            } else {
                r
            }
        };

        loop {
            if filter(next.0) {
                return Some(next);
            }

            next = self.iter.next()?;
        }
    }
}

#[derive(Debug)]
pub struct Peer<K, V, S: Store<K, V> = SimpleStore<K, V>>
where
    K: RangeKey + Clone + Default + AsFingerprint,
{
    store: S,
    /// Up to how many values to send immediately, before sending only a fingerprint.
    max_set_size: usize,
    /// `k` in the protocol, how many splits to generate. at least 2
    split_factor: usize,
    limit: Option<Range<K>>,

    _phantom: PhantomData<V>, // why???
}

impl<K, V, S> Default for Peer<K, V, S>
where
    K: RangeKey + Clone + Default + AsFingerprint,
    S: Store<K, V> + Default,
{
    fn default() -> Self {
        Peer {
            store: S::default(),
            max_set_size: 1,
            split_factor: 2,
            limit: None,
            _phantom: Default::default(),
        }
    }
}

impl<K, V, S> Peer<K, V, S>
where
    K: PartialEq + RangeKey + Clone + Default + Debug + AsFingerprint,
    V: Clone + Debug,
    S: Store<K, V> + Default,
{
    pub fn with_limit(limit: Range<K>) -> Self {
        Peer {
            store: S::default(),
            max_set_size: 1,
            split_factor: 2,
            limit: Some(limit),
            _phantom: Default::default(),
        }
    }
}
impl<K, V, S> Peer<K, V, S>
where
    K: PartialEq + RangeKey + Clone + Default + Debug + AsFingerprint,
    V: Clone + Debug,
    S: Store<K, V>,
{
    /// Generates the initial message.
    pub fn initial_message(&self) -> Message<K, V> {
        Message::init(&self.store, self.limit.as_ref())
    }

    /// Processes an incoming message and produces a response.
    /// If terminated, returns `None`
    pub fn process_message(&mut self, message: Message<K, V>) -> Option<Message<K, V>> {
        let mut out = Vec::new();

        // TODO: can these allocs be avoided?
        let mut items = Vec::new();
        let mut fingerprints = Vec::new();
        for part in message.parts {
            match part {
                MessagePart::RangeItem(item) => {
                    items.push(item);
                }
                MessagePart::RangeFingerprint(fp) => {
                    fingerprints.push(fp);
                }
            }
        }

        // Process item messages
        for RangeItem {
            range,
            values,
            have_local,
        } in items
        {
            let diff: Option<Vec<_>> = if have_local {
                None
            } else {
                Some(
                    self.store
                        .get_range(range.clone(), self.limit.clone())
                        .into_iter()
                        .filter(|(k, _)| !values.iter().any(|(vk, _)| &vk == k))
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                )
            };

            // Store incoming values
            for (k, v) in values {
                self.store.put(k, v);
            }

            if let Some(diff) = diff {
                if !diff.is_empty() {
                    out.push(MessagePart::RangeItem(RangeItem {
                        range,
                        values: diff,
                        have_local: true,
                    }));
                }
            }
        }

        // Process fingerprint messages
        for RangeFingerprint { range, fingerprint } in fingerprints {
            let local_fingerprint = self.store.get_fingerprint(&range, self.limit.as_ref());

            // Case1 Match, nothing to do
            if local_fingerprint == fingerprint {
                continue;
            }

            // Case2 Recursion Anchor
            let local_values: Vec<_> = self
                .store
                .get_range(range.clone(), self.limit.clone())
                .collect();
            if local_values.len() <= 1 || fingerprint == Fingerprint::empty() {
                let values = local_values
                    .into_iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                out.push(MessagePart::RangeItem(RangeItem {
                    range,
                    values,
                    have_local: false,
                }));
            } else {
                // Case3 Recurse
                // Create partition
                // m0 = x < m1 < .. < mk = y, with k>= 2
                // such that [ml, ml+1) is nonempty
                let mut ranges = Vec::with_capacity(self.split_factor);
                let chunk_len = div_ceil(local_values.len(), self.split_factor);

                // Select the first index, for which the key is larger than the x of the range.
                let mut start_index = local_values
                    .iter()
                    .position(|(k, _)| range.x() <= k)
                    .unwrap_or(0);
                let max_len = local_values.len();
                for i in 0..self.split_factor {
                    let s_index = start_index;
                    let start = (s_index * chunk_len) % max_len;
                    let e_index = s_index + 1;
                    let end = (e_index * chunk_len) % max_len;

                    let (x, y) = if i == 0 {
                        // first
                        (range.x(), local_values[end].0)
                    } else if i == self.split_factor - 1 {
                        // last
                        (local_values[start].0, range.y())
                    } else {
                        // regular
                        (local_values[start].0, local_values[end].0)
                    };
                    let range = Range::new(x.clone(), y.clone());
                    ranges.push(range);
                    start_index += 1;
                }

                for range in ranges.into_iter() {
                    let chunk: Vec<_> = self
                        .store
                        .get_range(range.clone(), self.limit.clone())
                        .collect();
                    // Add either the fingerprint or the item set
                    let fingerprint = self.store.get_fingerprint(&range, self.limit.as_ref());
                    if chunk.len() > self.max_set_size {
                        out.push(MessagePart::RangeFingerprint(RangeFingerprint {
                            range,
                            fingerprint,
                        }));
                    } else {
                        let values = chunk
                            .into_iter()
                            .map(|(k, v)| {
                                let k: K = k.clone();
                                let v: V = v.clone();
                                (k, v)
                            })
                            .collect();
                        out.push(MessagePart::RangeItem(RangeItem {
                            range,
                            values,
                            have_local: false,
                        }));
                    }
                }
            }
        }

        // If we have any parts, return a message
        if !out.is_empty() {
            Some(Message { parts: out })
        } else {
            None
        }
    }

    /// Insert a key value pair.
    pub fn put(&mut self, k: K, v: V) {
        self.store.put(k, v);
    }

    pub fn get(&self, k: &K) -> Option<&V> {
        self.store.get(k)
    }

    /// Remove the given key.
    pub fn remove(&mut self, k: &K) -> Option<V> {
        self.store.remove(k)
    }

    /// List all existing key value pairs.
    pub fn all(&self) -> impl Iterator<Item = (&K, &V)> {
        self.store.all()
    }

    /// Returns a refernce to the underlying store.
    pub fn store(&self) -> &S {
        &self.store
    }
}

/// Sadly https://doc.rust-lang.org/std/primitive.usize.html#method.div_ceil is still unstable..
fn div_ceil(a: usize, b: usize) -> usize {
    debug_assert!(a != 0);
    debug_assert!(b != 0);

    a / b + (a % b != 0) as usize
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use super::*;

    #[test]
    fn test_paper_1() {
        let alice_set = [("ape", 1), ("eel", 1), ("fox", 1), ("gnu", 1)];
        let bob_set = [
            ("bee", 1),
            ("cat", 1),
            ("doe", 1),
            ("eel", 1),
            ("fox", 1),
            ("hog", 1),
        ];

        let res = sync(None, &alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 2, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 2, "B -> A message count");

        // Initial message
        assert_eq!(res.alice_to_bob[0].parts.len(), 1);
        assert!(res.alice_to_bob[0].parts[0].is_range_fingerprint());

        // Response from Bob - recurse once
        assert_eq!(res.bob_to_alice[0].parts.len(), 2);
        assert!(res.bob_to_alice[0].parts[0].is_range_fingerprint());
        assert!(res.bob_to_alice[0].parts[1].is_range_fingerprint());

        // Last response from Alice
        assert_eq!(res.alice_to_bob[1].parts.len(), 3);
        assert!(res.alice_to_bob[1].parts[0].is_range_item());
        assert!(res.alice_to_bob[1].parts[1].is_range_fingerprint());
        assert!(res.alice_to_bob[1].parts[2].is_range_item());

        // Last response from Bob
        assert_eq!(res.bob_to_alice[1].parts.len(), 2);
        assert!(res.bob_to_alice[1].parts[0].is_range_item());
        assert!(res.bob_to_alice[1].parts[1].is_range_item());
    }

    #[test]
    fn test_paper_2() {
        let alice_set = [
            ("ape", 1),
            ("bee", 1),
            ("cat", 1),
            ("doe", 1),
            ("eel", 1),
            ("fox", 1), // the only value being sent
            ("gnu", 1),
            ("hog", 1),
        ];
        let bob_set = [
            ("ape", 1),
            ("bee", 1),
            ("cat", 1),
            ("doe", 1),
            ("eel", 1),
            ("gnu", 1),
            ("hog", 1),
        ];

        let res = sync(None, &alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 3, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 2, "B -> A message count");
    }

    #[test]
    fn test_paper_3() {
        let alice_set = [
            ("ape", 1),
            ("bee", 1),
            ("cat", 1),
            ("doe", 1),
            ("eel", 1),
            ("fox", 1),
            ("gnu", 1),
            ("hog", 1),
        ];
        let bob_set = [("ape", 1), ("cat", 1), ("eel", 1), ("gnu", 1)];

        let res = sync(None, &alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 3, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 2, "B -> A message count");
    }

    #[test]
    fn test_limits() {
        let alice_set = [("ape", 1), ("bee", 1), ("cat", 1)];
        let bob_set = [("ape", 1), ("cat", 1), ("doe", 1)];

        // No Limit
        let res = sync(None, &alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 3, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 2, "B -> A message count");

        // With Limit: just ape
        let limit = ("ape", "bee").into();
        let res = sync(Some(limit), &alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 1, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 0, "B -> A message count");

        // With Limit: just bee, cat
        let limit = ("bee", "doe").into();
        let res = sync(Some(limit), &alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 2, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 1, "B -> A message count");
    }

    #[test]
    fn test_prefixes_simple() {
        let alice_set = [("/foo/bar", 1), ("/foo/baz", 1), ("/foo/cat", 1)];
        let bob_set = [("/foo/bar", 1), ("/alice/bar", 1), ("/alice/baz", 1)];

        // No Limit
        let res = sync(None, &alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 2, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 2, "B -> A message count");

        // With Limit: just /alice
        let limit = ("/alice", "/b").into();
        let res = sync(Some(limit), &alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 1, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 1, "B -> A message count");
    }

    #[test]
    fn test_prefixes_empty_alice() {
        let alice_set = [];
        let bob_set = [("/foo/bar", 1), ("/alice/bar", 1), ("/alice/baz", 1)];

        // No Limit
        let res = sync(None, &alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 1, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 1, "B -> A message count");

        // With Limit: just /alice
        let limit = ("/alice", "/b").into();
        let res = sync(Some(limit), &alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 1, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 1, "B -> A message count");
    }

    #[test]
    fn test_prefixes_empty_bob() {
        let alice_set = [("/foo/bar", 1), ("/foo/baz", 1), ("/foo/cat", 1)];
        let bob_set = [];

        // No Limit
        let res = sync(None, &alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 2, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 1, "B -> A message count");

        // With Limit: just /alice
        let limit = ("/alice", "/b").into();
        let res = sync(Some(limit), &alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 1, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 0, "B -> A message count");
    }

    #[test]
    fn test_multikey() {
        #[derive(Default, Clone, PartialEq, Eq, PartialOrd, Ord)]
        struct Multikey {
            author: [u8; 4],
            key: Vec<u8>,
        }

        impl RangeKey for Multikey {
            fn contains(&self, range: &Range<Self>) -> bool {
                let author = range.x().author.cmp(&range.y().author);
                let key = range.x().key.cmp(&range.y().key);

                match (author, key) {
                    (Ordering::Equal, Ordering::Equal) => {
                        // All
                        true
                    }
                    (Ordering::Equal, Ordering::Less) => {
                        // Regular, based on key
                        range.x().key <= self.key && self.key < range.y().key
                    }
                    (Ordering::Equal, Ordering::Greater) => {
                        // Reverse, based on key
                        range.x().key <= self.key || self.key < range.y().key
                    }
                    (Ordering::Less, Ordering::Equal) => {
                        // Regular, based on author
                        range.x().author <= self.author && self.author < range.y().author
                    }
                    (Ordering::Greater, Ordering::Equal) => {
                        // Reverse, based on key
                        range.x().author <= self.author || self.author < range.y().author
                    }
                    (Ordering::Less, Ordering::Less) => {
                        // Regular, key and author
                        range.x().key <= self.key
                            && self.key < range.y().key
                            && range.x().author <= self.author
                            && self.author < range.y().author
                    }
                    (Ordering::Greater, Ordering::Greater) => {
                        // Reverse, key and author
                        (range.x().key <= self.key || self.key < range.y().key)
                            && (range.x().author <= self.author || self.author < range.y().author)
                    }
                    (Ordering::Less, Ordering::Greater) => {
                        // Regular author, Reverse key
                        (range.x().key <= self.key || self.key < range.y().key)
                            && (range.x().author <= self.author && self.author < range.y().author)
                    }
                    (Ordering::Greater, Ordering::Less) => {
                        // Regular key, Reverse author
                        (range.x().key <= self.key && self.key < range.y().key)
                            && (range.x().author <= self.author || self.author < range.y().author)
                    }
                }
            }
        }

        impl Debug for Multikey {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let key = if let Ok(key) = std::str::from_utf8(&self.key) {
                    key.to_string()
                } else {
                    hex::encode(&self.key)
                };
                f.debug_struct("Multikey")
                    .field("author", &hex::encode(self.author))
                    .field("key", &key)
                    .finish()
            }
        }
        impl AsFingerprint for Multikey {
            fn as_fingerprint(&self) -> Fingerprint {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&self.author);
                hasher.update(&self.key);
                Fingerprint(hasher.finalize().into())
            }
        }

        impl Multikey {
            fn new(author: [u8; 4], key: impl AsRef<[u8]>) -> Self {
                Multikey {
                    author,
                    key: key.as_ref().to_vec(),
                }
            }
        }
        let author_a = [1u8; 4];
        let author_b = [2u8; 4];
        let alice_set = [
            (Multikey::new(author_a, "ape"), 1),
            (Multikey::new(author_a, "bee"), 1),
            (Multikey::new(author_b, "bee"), 1),
            (Multikey::new(author_a, "doe"), 1),
        ];
        let bob_set = [
            (Multikey::new(author_a, "ape"), 1),
            (Multikey::new(author_a, "bee"), 1),
            (Multikey::new(author_a, "cat"), 1),
            (Multikey::new(author_b, "cat"), 1),
        ];

        // No limit
        let res = sync(None, &alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 2, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 2, "B -> A message count");
        res.assert_alice_set(
            "no limit",
            &[
                (Multikey::new(author_a, "ape"), 1),
                (Multikey::new(author_a, "bee"), 1),
                (Multikey::new(author_b, "bee"), 1),
                (Multikey::new(author_a, "doe"), 1),
                (Multikey::new(author_a, "cat"), 1),
                (Multikey::new(author_b, "cat"), 1),
            ],
        );

        res.assert_bob_set(
            "no limit",
            &[
                (Multikey::new(author_a, "ape"), 1),
                (Multikey::new(author_a, "bee"), 1),
                (Multikey::new(author_b, "bee"), 1),
                (Multikey::new(author_a, "doe"), 1),
                (Multikey::new(author_a, "cat"), 1),
                (Multikey::new(author_b, "cat"), 1),
            ],
        );

        // Only author_a
        let limit = Range::new(Multikey::new(author_a, ""), Multikey::new(author_b, ""));
        let res = sync(Some(limit), &alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 2, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 1, "B -> A message count");
        res.assert_alice_set(
            "only author_a",
            &[
                (Multikey::new(author_a, "ape"), 1),
                (Multikey::new(author_a, "bee"), 1),
                (Multikey::new(author_b, "bee"), 1),
                (Multikey::new(author_a, "doe"), 1),
                (Multikey::new(author_a, "cat"), 1),
            ],
        );

        res.assert_bob_set(
            "only author_a",
            &[
                (Multikey::new(author_a, "ape"), 1),
                (Multikey::new(author_a, "bee"), 1),
                (Multikey::new(author_a, "cat"), 1),
                (Multikey::new(author_b, "cat"), 1),
                (Multikey::new(author_a, "doe"), 1),
            ],
        );

        // All authors, but only cat
        let limit = Range::new(
            Multikey::new(author_a, "cat"),
            Multikey::new(author_a, "doe"),
        );
        let res = sync(Some(limit), &alice_set, &bob_set);
        assert_eq!(res.alice_to_bob.len(), 1, "A -> B message count");
        assert_eq!(res.bob_to_alice.len(), 1, "B -> A message count");

        res.assert_alice_set(
            "only cat",
            &[
                (Multikey::new(author_a, "ape"), 1),
                (Multikey::new(author_a, "bee"), 1),
                (Multikey::new(author_b, "bee"), 1),
                (Multikey::new(author_a, "doe"), 1),
                (Multikey::new(author_a, "cat"), 1),
                (Multikey::new(author_b, "cat"), 1),
            ],
        );

        res.assert_bob_set(
            "only cat",
            &[
                (Multikey::new(author_a, "ape"), 1),
                (Multikey::new(author_a, "bee"), 1),
                (Multikey::new(author_a, "cat"), 1),
                (Multikey::new(author_b, "cat"), 1),
            ],
        );
    }

    struct SyncResult<K, V>
    where
        K: RangeKey + Clone + Default + AsFingerprint,
    {
        alice: Peer<K, V>,
        bob: Peer<K, V>,
        alice_to_bob: Vec<Message<K, V>>,
        bob_to_alice: Vec<Message<K, V>>,
    }

    impl<K, V> SyncResult<K, V>
    where
        K: RangeKey + Clone + Default + AsFingerprint + Debug,
        V: Debug,
    {
        fn print_messages(&self) {
            let len = std::cmp::max(self.alice_to_bob.len(), self.bob_to_alice.len());
            for i in 0..len {
                if let Some(msg) = self.alice_to_bob.get(i) {
                    println!("A -> B:");
                    print_message(msg);
                }
                if let Some(msg) = self.bob_to_alice.get(i) {
                    println!("B -> A:");
                    print_message(msg);
                }
            }
        }
    }

    impl<K, V> SyncResult<K, V>
    where
        K: Debug + RangeKey + Clone + Default + AsFingerprint,
        V: Debug + Clone + PartialEq,
    {
        fn assert_alice_set(&self, ctx: &str, expected: &[(K, V)]) {
            dbg!(self.alice.all().collect::<Vec<_>>());
            for (k, v) in expected {
                assert_eq!(
                    self.alice.store.get(k),
                    Some(v),
                    "{}: (alice) missing key {:?}",
                    ctx,
                    k
                );
            }
            assert_eq!(expected.len(), self.alice.store.len(), "{}: (alice)", ctx);
        }

        fn assert_bob_set(&self, ctx: &str, expected: &[(K, V)]) {
            dbg!(self.bob.all().collect::<Vec<_>>());

            for (k, v) in expected {
                assert_eq!(
                    self.bob.store.get(k),
                    Some(v),
                    "{}: (bob) missing key {:?}",
                    ctx,
                    k
                );
            }
            assert_eq!(expected.len(), self.bob.store.len(), "{}: (bob)", ctx);
        }
    }

    fn print_message<K, V>(msg: &Message<K, V>)
    where
        K: Debug,
        V: Debug,
    {
        for part in &msg.parts {
            match part {
                MessagePart::RangeFingerprint(RangeFingerprint { range, fingerprint }) => {
                    println!(
                        "  RangeFingerprint({:?}, {:?}, {:?})",
                        range.x(),
                        range.y(),
                        fingerprint
                    );
                }
                MessagePart::RangeItem(RangeItem {
                    range,
                    values,
                    have_local,
                }) => {
                    println!(
                        "  RangeItem({:?} | {:?}) (local?: {})\n  {:?}",
                        range.x(),
                        range.y(),
                        have_local,
                        values,
                    );
                }
            }
        }
    }

    fn sync<K, V>(
        limit: Option<Range<K>>,
        alice_set: &[(K, V)],
        bob_set: &[(K, V)],
    ) -> SyncResult<K, V>
    where
        K: PartialEq + RangeKey + Clone + Default + Debug + AsFingerprint,
        V: Clone + Debug + PartialEq,
    {
        println!("Using Limit: {:?}", limit);
        let mut expected_set_alice = BTreeMap::new();
        let mut expected_set_bob = BTreeMap::new();

        let mut alice = if let Some(limit) = limit.clone() {
            Peer::<K, V>::with_limit(limit)
        } else {
            Peer::<K, V>::default()
        };
        for (k, v) in alice_set {
            alice.put(k.clone(), v.clone());

            let include = if let Some(ref limit) = limit {
                k.contains(limit)
            } else {
                true
            };
            if include {
                expected_set_bob.insert(k.clone(), v.clone());
            }
            // alices things are always in alices store
            expected_set_alice.insert(k.clone(), v.clone());
        }

        let mut bob = if let Some(limit) = limit.clone() {
            Peer::<K, V>::with_limit(limit)
        } else {
            Peer::<K, V>::default()
        };
        for (k, v) in bob_set {
            bob.put(k.clone(), v.clone());
            let include = if let Some(ref limit) = limit {
                k.contains(limit)
            } else {
                true
            };
            if include {
                expected_set_alice.insert(k.clone(), v.clone());
            }
            // bobs things are always in bobs store
            expected_set_bob.insert(k.clone(), v.clone());
        }

        let mut alice_to_bob = Vec::new();
        let mut bob_to_alice = Vec::new();
        let initial_message = alice.initial_message();

        let mut next_to_bob = Some(initial_message);
        let mut rounds = 0;
        while let Some(msg) = next_to_bob.take() {
            assert!(rounds < 100, "too many rounds");
            rounds += 1;
            alice_to_bob.push(msg.clone());

            if let Some(msg) = bob.process_message(msg) {
                bob_to_alice.push(msg.clone());
                next_to_bob = alice.process_message(msg);
            }
        }
        let res = SyncResult {
            alice,
            bob,
            alice_to_bob,
            bob_to_alice,
        };
        res.print_messages();

        let alice_now: Vec<_> = res.alice.all().collect();
        assert_eq!(
            expected_set_alice.iter().collect::<Vec<_>>(),
            alice_now,
            "alice"
        );

        let bob_now: Vec<_> = res.bob.all().collect();
        assert_eq!(expected_set_bob.iter().collect::<Vec<_>>(), bob_now, "bob");

        // Check that values were never sent twice
        let mut alice_sent = BTreeMap::new();
        for msg in &res.alice_to_bob {
            for part in &msg.parts {
                if let Some(values) = part.values() {
                    for (key, value) in values {
                        assert!(
                            alice_sent.insert(key.clone(), value.clone()).is_none(),
                            "alice: duplicate {:?} - {:?}",
                            key,
                            value
                        );
                    }
                }
            }
        }

        let mut bob_sent = BTreeMap::new();
        for msg in &res.bob_to_alice {
            for part in &msg.parts {
                if let Some(values) = part.values() {
                    for (key, value) in values {
                        assert!(
                            bob_sent.insert(key.clone(), value.clone()).is_none(),
                            "bob: duplicate {:?} - {:?}",
                            key,
                            value
                        );
                    }
                }
            }
        }

        res
    }

    #[test]
    fn store_get_range() {
        let mut store = SimpleStore::<&'static str, usize>::default();
        let set = [
            ("bee", 1),
            ("cat", 1),
            ("doe", 1),
            ("eel", 1),
            ("fox", 1),
            ("hog", 1),
        ];
        for (k, v) in &set {
            store.put(*k, *v);
        }

        let all: Vec<_> = store
            .get_range(Range::new("", ""), None)
            .into_iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        assert_eq!(&all, &set[..]);

        let regular: Vec<_> = store
            .get_range(("bee", "eel").into(), None)
            .into_iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        assert_eq!(&regular, &set[..3]);

        // empty start
        let regular: Vec<_> = store
            .get_range(("", "eel").into(), None)
            .into_iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        assert_eq!(&regular, &set[..3]);

        let regular: Vec<_> = store
            .get_range(("cat", "hog").into(), None)
            .into_iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        assert_eq!(&regular, &set[1..5]);

        let excluded: Vec<_> = store
            .get_range(("fox", "bee").into(), None)
            .into_iter()
            .map(|(k, v)| (*k, *v))
            .collect();

        assert_eq!(excluded[0].0, "fox");
        assert_eq!(excluded[1].0, "hog");
        assert_eq!(excluded.len(), 2);

        let excluded: Vec<_> = store
            .get_range(("fox", "doe").into(), None)
            .into_iter()
            .map(|(k, v)| (*k, *v))
            .collect();

        assert_eq!(excluded.len(), 4);
        assert_eq!(excluded[0].0, "bee");
        assert_eq!(excluded[1].0, "cat");
        assert_eq!(excluded[2].0, "fox");
        assert_eq!(excluded[3].0, "hog");

        // Limit
        let all: Vec<_> = store
            .get_range(("", "").into(), Some(("bee", "doe").into()))
            .into_iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        assert_eq!(&all, &set[..2]);
    }

    #[test]
    fn test_div_ceil() {
        assert_eq!(div_ceil(1, 1), 1);
        assert_eq!(div_ceil(2, 1), 2);
        assert_eq!(div_ceil(4, 2), 4 / 2);

        assert_eq!(div_ceil(3, 2), 2);
        assert_eq!(div_ceil(5, 3), 2);
    }
}
