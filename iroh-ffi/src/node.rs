use anyhow::Result;
use safer_ffi::prelude::*;
use tokio::Runtime;

use iroh::{
    node::{Node, DEFAULT_BIND_ADDR},
    provider::Database,
};
use iroh_net::tls::Keypair;

#[derive_ReprC(rename = "iroh_node")]
#[repr(opaque)]
/// @class iroh_node_t
pub struct IrohNode {
    inner: Node,
    async_runtime: Arc<TokioRuntime>,
}

impl IrohNode {
    // pub fn new() -> Result<Self> {
    //     todo!()
    // }

    pub fn async_runtime(&self) -> Arc<Runtime> {
        self.async_runtime.clone()
    }

    pub fn inner(&self) -> &Node {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut Node {
        &mut self.inner
    }
}

#[ffi_export]
/// @memberof iroh_node_t
/// Initialize a iroh_node_t instance.
///
pub fn iroh_initialize() -> Option<repr_c::Box<IrohNode>> {
    let tokio_rt = tokio::runtime::Builder::new_multi_thread()
        .thread_name("main-runtime")
        .worker_threads(2)
        .enable_all()
        .build()?;

    let tokio = tokio::runtime::Handle::current();
    let tpc = tokio_util::task::LocalPoolHandle::new(num_cpus::get());
    let rt = iroh::bytes::runtime::Handle::new(tokio, tpc);

    let db = Database::default();
    let keypair = Keypair::generate();
    let node = Node::builder(db)
        .bind_addr(DEFAULT_BIND_ADDR)
        .keypair(keypair)
        .runtime(rt)
        .spawn()
        .await?;

    repr_c::Box::new(IrohNode {
        inner: node,
        runtime: tokio_rt,
    })
    .ok()
}
