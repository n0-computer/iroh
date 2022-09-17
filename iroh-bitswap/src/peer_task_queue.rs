//! Based on https://github.com/ipfs/go-peertaskqueue.

use std::{fmt::Debug, marker::PhantomData};

use cid::Cid;
use libp2p::PeerId;

#[derive(Debug, Clone)]
pub struct PeerTaskQueue<T: Topic, D: Data> {
    _p: PhantomData<(T, D)>,
}

impl<T: Topic, D: Data> PeerTaskQueue<T, D> {
    pub fn new() -> Self {
        todo!()
    }

    pub fn pop_tasks(&self, target_min_work: usize) -> (PeerId, Vec<Task<T, D>>, Option<usize>) {
        todo!()
    }

    pub fn push_tasks(&self, peer: PeerId, tasks: Vec<Task<T, D>>) {
        todo!()
    }

    pub fn remove(&self, cid: Cid, peer: PeerId) {
        todo!()
    }
}

#[derive(Debug)]
pub struct Task<T: Topic, D: Data> {
    pub topic: T,
    pub priority: isize,
    pub work: usize,
    pub data: D,
}

pub trait Topic: Sized + Debug {}
impl Topic for Cid {}

pub trait Data: Sized + Debug {}
