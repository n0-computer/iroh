// // use iroh_net::NodeId
// use anyhow::Result;
// use tokio::task::JoinSet;
// use tokio::sync::mpsc;
//
// use crate::{packet::Announcement, NodeId};
//
// // pub enum ResolveError {
// //     NotFound,
// //     F
// // }
//
// pub trait Resolver: Send {
//     fn resolve(&self, node_id: NodeId) -> impl Stream<Item = Result<Announcement>> + Send + 'static;
// }
//
// pub trait Publisher: Send {
//     fn publish(&self, announcement: Announcement) -> impl Future<Output = Result<()>> + Send + 'static;
// }
//
// pub struct Client {
//     tasks: JoinSet,
//     // queries: 
// }
//
// impl Client {
//     fn resolve(&self, node_id: NodeId) -> impl Stream<Item = Result<Announcement>> {
//         let (tx, rx) = mpsc::channel(1);
//
//     }
//     async fn resolve_one(&self, node_id: NodeId) -> Result<Announcement> {
//
//     }
//     fn add_resolver(&mut self, resolver: impl Resolver) {
//         self.tasks.spawn(async move {
//
//
//         })
//     }
// }
