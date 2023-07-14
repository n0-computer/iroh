use std::sync::Arc;

use safer_ffi::prelude::*;
use tokio::runtime::Runtime as TokioRuntime;

use iroh::{
    database::mem,
    net::tls::Keypair,
    node::{Node, DEFAULT_BIND_ADDR},
};

#[derive_ReprC(rename = "iroh_node")]
#[repr(opaque)]
/// @class iroh_node_t
pub struct IrohNode {
    inner: Node<mem::Database>,
    async_runtime: Arc<TokioRuntime>,
}

impl IrohNode {
    pub fn async_runtime(&self) -> Arc<TokioRuntime> {
        self.async_runtime.clone()
    }

    pub fn inner(&self) -> &Node<mem::Database> {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut Node<mem::Database> {
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
        .build()
        .ok()?;

    let tokio = tokio::runtime::Handle::current();
    let tpc = tokio_util::task::LocalPoolHandle::new(num_cpus::get());
    let rt = iroh::bytes::util::runtime::Handle::new(tokio, tpc);

    let db = mem::Database::default();
    let keypair = Keypair::generate();
    let node = tokio_rt
        .block_on(async {
            Node::builder(db)
                .bind_addr(DEFAULT_BIND_ADDR.into())
                .keypair(keypair)
                .runtime(&rt)
                .spawn()
                .await
        })
        .unwrap();

    Some(
        Box::new(IrohNode {
            inner: node,
            async_runtime: Arc::new(tokio_rt),
        })
        .into(),
    )
}

#[ffi_export]
/// @memberof iroh_node_t
/// Deallocate a ns_noosphere_t instance.
pub fn iroh_free(node: repr_c::Box<IrohNode>) {
    drop(node)
}
