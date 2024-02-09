//! Utilities for timers

use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

#[cfg(feature = "tokio")]
pub use tokio_timers::*;

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

#[cfg(feature = "tokio")]
mod tokio_timers {
    use std::{pin::Pin, time::Instant};
    use tokio::time::{sleep_until, Sleep};

    use super::TimerMap;

    /// A [`TimerMap`] with an async method to wait for the next timer expiration.
    #[derive(Debug)]
    pub struct Timers<T> {
        next: Option<(Instant, Pin<Box<Sleep>>)>,
        map: TimerMap<T>,
    }

    impl<T> Default for Timers<T> {
        fn default() -> Self {
            Self {
                next: None,
                map: TimerMap::default(),
            }
        }
    }

    impl<T> Timers<T> {
        /// Create a new timer map
        pub fn new() -> Self {
            Self::default()
        }

        /// Insert a new entry at the specified instant
        pub fn insert(&mut self, instant: Instant, item: T) {
            self.map.insert(instant, item);
        }

        fn reset(&mut self) {
            self.next = self
                .map
                .first()
                .map(|(instant, _)| (*instant, Box::pin(sleep_until((*instant).into()))))
        }

        /// Wait for the next timer to expire and return an iterator of all expired timers
        ///
        /// If the [TimerMap] is empty, this will return a future that is pending forever.
        /// After inserting a new entry, prior futures returned from this method will not become ready.
        /// They should be dropped after calling [Self::insert], and a new future as returned from
        /// this method should be awaited instead.
        pub async fn wait_and_drain(&mut self) -> impl Iterator<Item = (Instant, T)> {
            self.reset();
            match self.next.as_mut() {
                Some((instant, sleep)) => {
                    sleep.await;
                    self.map.drain_until(instant)
                }
                None => std::future::pending().await,
            }
        }
        /// Iterate over all items in the timer map.
        pub fn iter(&self) -> impl Iterator<Item = (&Instant, &T)> {
            self.map.iter()
        }
    }
}

#[cfg(test)]
mod test {
    use std::time::{Duration, Instant};

    use super::TimerMap;

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
}
