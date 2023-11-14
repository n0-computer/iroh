use std::{
    collections::{HashSet, VecDeque},
    marker::PhantomData,
};

#[derive(Debug)]
pub struct IdGenerator<T>(u64, PhantomData<T>);

impl<T> Default for IdGenerator<T> {
    fn default() -> Self {
        Self(0, PhantomData)
    }
}

impl<T: From<u64>> IdGenerator<T> {
    pub fn next(&mut self) -> T {
        let next = self.0;
        self.0 += 1;
        next.into()
    }
}

#[derive(Debug)]
pub struct IndexSet<T> {
    items: HashSet<T>,
    order: VecDeque<T>,
}
impl<T> Default for IndexSet<T> {
    fn default() -> Self {
        Self {
            items: Default::default(),
            order: Default::default(),
        }
    }
}
impl<T: std::hash::Hash + Eq + PartialEq + Copy> IndexSet<T> {
    pub fn contains(&self, item: &T) -> bool {
        self.items.contains(item)
    }

    pub fn insert(&mut self, item: T) -> bool {
        if self.items.insert(item) {
            self.order.push_back(item);
            true
        } else {
            false
        }
    }
    pub fn push_front(&mut self, item: T) -> bool {
        if self.items.insert(item) {
            self.order.push_front(item);
            true
        } else {
            false
        }
    }

    pub fn pop_front(&mut self) -> Option<T> {
        if let Some(item) = self.order.pop_front() {
            self.items.remove(&item);
            Some(item)
        } else {
            None
        }
    }

    pub fn pop_back(&mut self) -> Option<T> {
        if let Some(item) = self.order.pop_back() {
            self.items.remove(&item);
            Some(item)
        } else {
            None
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> + '_ {
        self.order.iter()
    }

    pub fn remove(&mut self, item: &T) -> bool {
        let res = self.items.remove(item);
        self.order.retain(|x| x != item);
        res
    }

    pub fn drain(&mut self) -> Drain<'_, T> {
        Drain::new(self)
    }
}

pub struct Drain<'a, T> {
    inner: &'a mut IndexSet<T>,
}
impl<'a, T> Drain<'a, T> {
    fn new(inner: &'a mut IndexSet<T>) -> Self {
        Self { inner }
    }
}
impl<'a, T: std::hash::Hash + Eq + PartialEq> Iterator for Drain<'a, T> {
    type Item = T;
    fn next(&mut self) -> Option<Self::Item> {
        let item = self.inner.order.pop_front();
        if let Some(ref item) = item {
            self.inner.items.remove(&item);
        }
        item
    }
}
