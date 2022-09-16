//! Based on https://github.com/ipfs/go-peertaskqueue.

use std::fmt::Debug;

use cid::Cid;

#[derive(Debug)]
pub struct PeerTaskQueue {}

#[derive(Debug)]
pub struct Task<T: Topic, D: Data> {
    pub topic: T,
    pub priority: usize,
    pub work: usize,
    pub data: D,
}

pub trait Topic: Sized + Debug {}
impl Topic for Cid {}

pub trait Data: Sized + Debug {}
