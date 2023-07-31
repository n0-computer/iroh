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

/// A hash set where the iteration order of the values is independent of their
/// hash values.
///
/// This is wrapper around [indexmap::IndexSet] that limits the removal API to
/// always do shift_remove (preserving the order of other elements) and adds a
/// couple of utility methods to randomly select elements from the set.
#[derive(Debug, Clone)]
pub(crate) struct IndexSet<T> {
    inner: indexmap::IndexSet<T>,
}

impl<T: Hash + Eq + PartialEq> Default for IndexSet<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Hash + Eq + PartialEq> IndexSet<T> {
    pub fn new() -> Self {
        Self {
            inner: indexmap::IndexSet::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
    pub fn insert(&mut self, value: T) -> bool {
        self.inner.insert(value)
    }

    pub fn contains(&self, value: &T) -> bool {
        self.inner.contains(value)
    }

    pub fn get_index_of(&self, value: &T) -> Option<usize> {
        self.inner.get_index_of(value)
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

    /// Remove an element from the set, while keeping the order of the other elements.
    pub fn remove(&mut self, value: &T) -> Option<T> {
        self.inner.shift_remove_full(value).map(|(_i, v)| v)
    }

    /// Remove an element from the set by its index.
    pub fn remove_index(&mut self, index: usize) -> Option<T> {
        self.inner.shift_remove_index(index)
    }

    /// Create an iterator over the set in the order of insertion.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.inner.iter()
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

impl<T> Default for TimerMap<T> {
    fn default() -> Self {
        Self::new()
    }
}
