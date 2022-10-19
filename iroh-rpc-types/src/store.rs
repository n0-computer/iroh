use bytes::{Bytes, BytesMut};
use cid::Cid;

use crate::RpcError;

#[tarpc::service]
pub trait Store {
    async fn version() -> Result<String, RpcError>;
    async fn put(cid: Cid, bytes: Bytes, links: Vec<Cid>) -> Result<(), RpcError>;
    async fn put_many(blocks: Vec<(Cid, Bytes, Vec<Cid>)>) -> Result<(), RpcError>;
    async fn get(cid: Cid) -> Result<Option<BytesMut>, RpcError>;
    async fn has(cid: Cid) -> Result<bool, RpcError>;
    async fn get_links(cid: Cid) -> Result<Vec<Cid>, RpcError>;
    async fn get_size(cid: Cid) -> Result<Option<u64>, RpcError>;
}
