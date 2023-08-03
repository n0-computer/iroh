//! Utilities used in the protocol implementation

use rand::{
    seq::{IteratorRandom, SliceRandom},
    Rng,
};
use std::{
    collections::BTreeMap,
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

        impl<T: Into<[u8; 32]>> From<T> for $ty {
            fn from(value: T) -> Self {
                Self::from_bytes(value.into())
            }
        }

        impl std::fmt::Display for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "{}", $crate::proto::util::base32::fmt(&self.0))
            }
        }

        impl std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(
                    f,
                    "{}({}…)",
                    $name,
                    $crate::proto::util::base32::fmt_short(&self.0)
                )
            }
        }

        impl std::str::FromStr for $ty {
            type Err = ::anyhow::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(Self::from_bytes($crate::proto::util::base32::parse_array(
                    s,
                )?))
            }
        }

        impl AsRef<[u8]> for $ty {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl AsRef<[u8; 32]> for $ty {
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

/// A [`BTreeMap`] with [`Instant`] as key. Allows to process expired items.
#[derive(Debug)]
pub struct TimerMap<T>(BTreeMap<Instant, Vec<T>>);

impl<T> Default for TimerMap<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> TimerMap<T> {
    /// Create a new, empty TimerMap
    pub fn new() -> Self {
        Self(Default::default())
    }
    /// Insert a new entry at the specified instant
    pub fn insert(&mut self, instant: Instant, item: T) {
        let entry = self.0.entry(instant).or_default();
        entry.push(item);
    }

    /// Remove and return all entries before and equal to `from`
    pub fn drain_until(&mut self, from: &Instant) -> impl Iterator<Item = (Instant, T)> {
        let split_point = *from + Duration::from_nanos(1);
        let later_half = self.0.split_off(&split_point);
        let expired = std::mem::replace(&mut self.0, later_half);
        expired
            .into_iter()
            .flat_map(|(t, v)| v.into_iter().map(move |v| (t, v)))
    }

    /// Get a reference to the earliest entry in the TimerMap
    pub fn first(&self) -> Option<(&Instant, &Vec<T>)> {
        self.0.iter().next()
    }
}
