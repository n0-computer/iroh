//! Utilities used in the protocol implementation

use rand::{
    seq::{IteratorRandom, SliceRandom},
    Rng,
};
use std::{
    collections::{BTreeMap, HashMap},
    hash::Hash,
    time::{Duration, Instant},
};

/// Utilities for working with byte array identifiers
pub mod base32 {
    /// Convert to a base32 string
    pub fn fmt(bytes: impl AsRef<[u8]>) -> String {
        let mut text = data_encoding::BASE32_NOPAD.encode(bytes.as_ref());
        text.make_ascii_lowercase();
        text
    }
    /// Convert to a base32 string limited to the first 10 bytes
    pub fn fmt_short(bytes: impl AsRef<[u8]>) -> String {
        let len = bytes.as_ref().len().min(10);
        let mut text = data_encoding::BASE32_NOPAD.encode(&bytes.as_ref()[..len]);
        text.make_ascii_lowercase();
        text.push('…');
        text
    }
    /// Parse from a base32 string into a byte array
    pub fn parse_array<const N: usize>(input: &str) -> anyhow::Result<[u8; N]> {
        data_encoding::BASE32_NOPAD
            .decode(input.to_ascii_uppercase().as_bytes())?
            .try_into()
            .map_err(|_| ::anyhow::anyhow!("Failed to parse: invalid byte length"))
    }
    /// Decode form a base32 string to a vector of bytes
    pub fn parse_vec(input: &str) -> anyhow::Result<Vec<u8>> {
        data_encoding::BASE32_NOPAD
            .decode(input.to_ascii_uppercase().as_bytes())
            .map_err(Into::into)
    }
}

/// Implement methods, display, debug and conversion traits for 32 byte identifiers.
macro_rules! idbytes_impls {
    ($ty:ty, $name:expr) => {
        impl $ty {
            /// Create from a byte array.
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Get as byte slice.
            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl<T: ::std::convert::Into<[u8; 32]>> ::std::convert::From<T> for $ty {
            fn from(value: T) -> Self {
                Self::from_bytes(value.into())
            }
        }

        impl ::std::fmt::Display for $ty {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                write!(f, "{}", $crate::proto::util::base32::fmt(&self.0))
            }
        }

        impl ::std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                write!(
                    f,
                    "{}({})",
                    $name,
                    $crate::proto::util::base32::fmt_short(&self.0)
                )
            }
        }

        impl ::std::str::FromStr for $ty {
            type Err = ::anyhow::Error;
            fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
                Ok(Self::from_bytes($crate::proto::util::base32::parse_array(
                    s,
                )?))
            }
        }

        impl ::std::convert::AsRef<[u8]> for $ty {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl ::std::convert::AsRef<[u8; 32]> for $ty {
            fn as_ref(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

pub(crate) use idbytes_impls;

/// A hash set where the iteration order of the values is independent of their
/// hash values.
///
/// This is wrapper around [indexmap::IndexSet] which couple of utility methods
/// to randomly select elements from the set.
#[derive(Default, Debug, Clone, derive_more::Deref)]
pub(crate) struct IndexSet<T> {
    inner: indexmap::IndexSet<T>,
}

impl<T: Hash + Eq> PartialEq for IndexSet<T> {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl<T: Hash + Eq + PartialEq> IndexSet<T> {
    pub fn new() -> Self {
        Self {
            inner: indexmap::IndexSet::new(),
        }
    }

    pub fn insert(&mut self, value: T) -> bool {
        self.inner.insert(value)
    }

    /// Remove a random element from the set.
    pub fn remove_random<R: Rng + ?Sized>(&mut self, rng: &mut R) -> Option<T> {
        self.pick_random_index(rng)
            .and_then(|idx| self.inner.shift_remove_index(idx))
    }

    /// Pick a random element from the set.
    pub fn pick_random<R: Rng + ?Sized>(&self, rng: &mut R) -> Option<&T> {
        self.pick_random_index(rng)
            .and_then(|idx| self.inner.get_index(idx))
    }

    /// Pick a random element from the set, but not any of the elements in `without`.
    pub fn pick_random_without<R: Rng + ?Sized>(&self, without: &[&T], rng: &mut R) -> Option<&T> {
        self.iter().filter(|x| !without.contains(x)).choose(rng)
    }

    /// Pick a random index for an element in the set.
    pub fn pick_random_index<R: Rng + ?Sized>(&self, rng: &mut R) -> Option<usize> {
        if self.is_empty() {
            None
        } else {
            Some(rng.gen_range(0..self.inner.len()))
        }
    }

    /// Remove an element from the set.
    ///
    /// NOTE: the value is removed by swapping it with the last element of the set and popping it off.
    /// **This modifies the order of element by moving the last element**
    pub fn remove(&mut self, value: &T) -> Option<T> {
        self.inner.swap_remove_full(value).map(|(_i, v)| v)
    }

    /// Remove an element from the set by its index.
    ///
    /// NOTE: the value is removed by swapping it with the last element of the set and popping it off.
    /// **This modifies the order of element by moving the last element**
    pub fn remove_index(&mut self, index: usize) -> Option<T> {
        self.inner.swap_remove_index(index)
    }

    /// Create an iterator over the set in the order of insertion, while skipping the element in
    /// `without`.
    pub fn iter_without<'a>(&'a self, value: &'a T) -> impl Iterator<Item = &'a T> {
        self.iter().filter(move |x| *x != value)
    }
}

impl<T> IndexSet<T>
where
    T: Hash + Eq + Clone,
{
    /// Create a vector of all elements in the set in random order.
    pub fn shuffled<R: Rng + ?Sized>(&self, rng: &mut R) -> Vec<T> {
        let mut items: Vec<_> = self.inner.iter().cloned().collect();
        items.shuffle(rng);
        items
    }

    /// Create a vector of all elements in the set in random order, and shorten to
    /// the first `len` elements after shuffling.
    pub fn shuffled_and_capped<R: Rng + ?Sized>(&self, len: usize, rng: &mut R) -> Vec<T> {
        let mut items = self.shuffled(rng);
        items.truncate(len);
        items
    }

    /// Create a vector of the elements in the set in random order while omitting
    /// the elements in `without`.
    pub fn shuffled_without<R: Rng + ?Sized>(&self, without: &[&T], rng: &mut R) -> Vec<T> {
        let mut items = self
            .inner
            .iter()
            .filter(|x| !without.contains(x))
            .cloned()
            .collect::<Vec<_>>();
        items.shuffle(rng);
        items
    }

    /// Create a vector of the elements in the set in random order while omitting
    /// the elements in `without`, and shorten to the first `len` elements.
    pub fn shuffled_without_and_capped<R: Rng + ?Sized>(
        &self,
        without: &[&T],
        len: usize,
        rng: &mut R,
    ) -> Vec<T> {
        let mut items = self.shuffled_without(without, rng);
        items.truncate(len);
        items
    }
}

impl<T> IntoIterator for IndexSet<T> {
    type Item = T;
    type IntoIter = <indexmap::IndexSet<T> as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<T> FromIterator<T> for IndexSet<T>
where
    T: Hash + Eq,
{
    fn from_iter<I: IntoIterator<Item = T>>(iterable: I) -> Self {
        IndexSet {
            inner: indexmap::IndexSet::from_iter(iterable),
        }
    }
}

/// A [`BTreeMap`] with [`Instant`] as key. Allows to process expired items.
#[derive(Debug)]
pub struct TimerMap<T>(BTreeMap<Instant, Vec<T>>);

impl<T> Default for TimerMap<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> TimerMap<T> {
    /// Create a new, empty TimerMap.
    pub fn new() -> Self {
        Self(Default::default())
    }
    /// Insert a new entry at the specified instant.
    pub fn insert(&mut self, instant: Instant, item: T) {
        let entry = self.0.entry(instant).or_default();
        entry.push(item);
    }

    /// Remove and return all entries before and equal to `from`.
    pub fn drain_until(&mut self, from: &Instant) -> impl Iterator<Item = (Instant, T)> {
        let split_point = *from + Duration::from_nanos(1);
        let later_half = self.0.split_off(&split_point);
        let expired = std::mem::replace(&mut self.0, later_half);
        expired
            .into_iter()
            .flat_map(|(t, v)| v.into_iter().map(move |v| (t, v)))
    }

    /// Get a reference to the earliest entry in the TimerMap.
    pub fn first(&self) -> Option<(&Instant, &Vec<T>)> {
        self.0.iter().next()
    }

    /// Iterate over all items in the timer map.
    pub fn iter(&self) -> impl Iterator<Item = (&Instant, &T)> {
        self.0
            .iter()
            .flat_map(|(t, v)| v.iter().map(move |v| (t, v)))
    }
}

impl<T: PartialEq> TimerMap<T> {
    /// Remove an entry from the specified instant.
    pub fn remove(&mut self, instant: &Instant, item: &T) {
        if let Some(items) = self.0.get_mut(instant) {
            items.retain(|x| x != item)
        }
    }
}

/// A hash map where entries expire after a time
#[derive(Debug)]
pub struct TimeBoundCache<K, V> {
    map: HashMap<K, (Instant, V)>,
    expiry: TimerMap<K>,
}

impl<K, V> Default for TimeBoundCache<K, V> {
    fn default() -> Self {
        Self {
            map: Default::default(),
            expiry: Default::default(),
        }
    }
}

impl<K: Hash + Eq + Clone, V> TimeBoundCache<K, V> {
    /// Insert an item into the cache, marked with an expiration time.
    pub fn insert(&mut self, key: K, value: V, expires: Instant) {
        self.remove(&key);
        self.map.insert(key.clone(), (expires, value));
        self.expiry.insert(expires, key);
    }

    /// Returns `true` if the map contains a value for the specified key.
    pub fn contains_key(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    /// Remove an item from the cache.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        if let Some((expires, value)) = self.map.remove(key) {
            self.expiry.remove(&expires, key);
            Some(value)
        } else {
            None
        }
    }

    /// Get the number of entries in the cache.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns `true` if the map contains no elements.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Get an item from the cache.
    pub fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key).map(|(_expires, value)| value)
    }

    /// Get the expiration time for an item.
    pub fn expires(&self, key: &K) -> Option<&Instant> {
        self.map.get(key).map(|(expires, _value)| expires)
    }

    /// Iterate over all items in the cache.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V, &Instant)> {
        self.map.iter().map(|(k, (expires, v))| (k, v, expires))
    }

    /// Remove all entries with an expiry instant lower or equal to `instant`.
    ///
    /// Returns the number of items that were removed.
    pub fn expire_until(&mut self, instant: Instant) -> usize {
        let drain = self.expiry.drain_until(&instant);
        let mut count = 0;
        for (_instant, key) in drain {
            count += 1;
            let _value = self.map.remove(&key);
        }
        count
    }
}

#[cfg(test)]
mod test {
    use std::{
        str::FromStr,
        time::{Duration, Instant},
    };

    use rand_core::SeedableRng;

    use super::{IndexSet, TimeBoundCache, TimerMap};

    fn test_rng() -> rand_chacha::ChaCha12Rng {
        rand_chacha::ChaCha12Rng::seed_from_u64(42)
    }

    #[test]
    fn indexset() {
        let elems = [1, 2, 3, 4];
        let set = IndexSet::from_iter(elems);
        let x = set.shuffled(&mut test_rng());
        assert_eq!(x, vec![4, 2, 1, 3]);
        let x = set.shuffled_and_capped(2, &mut test_rng());
        assert_eq!(x, vec![4, 2]);
        let x = set.shuffled_without(&[&1], &mut test_rng());
        assert_eq!(x, vec![4, 3, 2]);
        let x = set.shuffled_without_and_capped(&[&1], 2, &mut test_rng());
        assert_eq!(x, vec![4, 3]);

        // recreate the rng - otherwise we get failures on some architectures when cross-compiling,
        // likely due to usize differences pulling different amounts of randomness.
        let x = set.pick_random(&mut test_rng());
        assert_eq!(x, Some(&3));
        let x = set.pick_random_without(&[&3], &mut test_rng());
        assert_eq!(x, Some(&4));

        let mut set = set;
        set.remove_random(&mut test_rng());
        assert_eq!(set, IndexSet::from_iter([1, 2, 4]));
    }

    #[test]
    fn timer_map() {
        let mut map = TimerMap::new();
        let now = Instant::now();

        let times = [
            now - Duration::from_secs(1),
            now,
            now + Duration::from_secs(1),
            now + Duration::from_secs(2),
        ];
        map.insert(times[0], -1);
        map.insert(times[0], -2);
        map.insert(times[1], 0);
        map.insert(times[2], 1);
        map.insert(times[3], 2);
        map.insert(times[3], 3);

        assert_eq!(
            map.iter().collect::<Vec<_>>(),
            vec![
                (&times[0], &-1),
                (&times[0], &-2),
                (&times[1], &0),
                (&times[2], &1),
                (&times[3], &2),
                (&times[3], &3)
            ]
        );

        assert_eq!(map.first(), Some((&times[0], &vec![-1, -2])));

        let drain = map.drain_until(&now);
        assert_eq!(
            drain.collect::<Vec<_>>(),
            vec![(times[0], -1), (times[0], -2), (times[1], 0),]
        );
        assert_eq!(
            map.iter().collect::<Vec<_>>(),
            vec![(&times[2], &1), (&times[3], &2), (&times[3], &3)]
        );
    }

    #[test]
    fn base32() {
        #[derive(Eq, PartialEq)]
        struct Id([u8; 32]);
        idbytes_impls!(Id, "Id");
        let id: Id = [1u8; 32].into();
        assert_eq!(id, Id::from_str(&format!("{id}")).unwrap());
        assert_eq!(
            &format!("{id}"),
            "aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq"
        );
        assert_eq!(&format!("{id:?}"), "Id(aeaqcaibaeaqcaib…)");
        assert_eq!(id.as_bytes(), &[1u8; 32]);
    }

    #[test]
    fn time_bound_cache() {
        let mut cache = TimeBoundCache::default();

        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(1);
        let t2 = t0 + Duration::from_secs(2);

        cache.insert(1, 10, t0);
        cache.insert(2, 20, t1);
        cache.insert(3, 30, t1);
        cache.insert(4, 40, t2);

        assert_eq!(cache.get(&2), Some(&20));
        assert_eq!(cache.len(), 4);
        let removed = cache.expire_until(t1);
        assert_eq!(removed, 3);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&2), None);
        assert_eq!(cache.get(&4), Some(&40));

        let t3 = t2 + Duration::from_secs(1);
        cache.insert(5, 50, t2);
        assert_eq!(cache.expires(&5), Some(&t2));
        cache.insert(5, 50, t3);
        assert_eq!(cache.expires(&5), Some(&t3));
        cache.expire_until(t2);
        assert_eq!(cache.get(&4), None);
        assert_eq!(cache.get(&5), Some(&50));
    }
}
