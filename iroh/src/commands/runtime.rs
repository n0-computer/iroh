use std::{cell::RefCell, path::PathBuf, rc::Rc};

use anyhow::Result;
use deno_core::{
    error::AnyError, op2, AsyncRefCell, FsModuleLoader, ModuleSpecifier, OpState, RcRef, Resource,
    ResourceId,
};
use deno_runtime::{
    permissions::PermissionsContainer,
    worker::{MainWorker, WorkerOptions},
    BootstrapOptions,
};

use futures::{stream::BoxStream, StreamExt};
use iroh::{
    client::mem::{Doc, Iroh},
    rpc_protocol::NodeStatusResponse,
    sync_engine::LiveEvent,
};

pub(crate) async fn exec(iroh: &Iroh, js_path: PathBuf) -> Result<()> {
    deno_core::extension!(
        iroh_runtime,
        ops = [op_node_status, op_doc_subscribe, op_next_doc_event],
        esm_entry_point = "ext:iroh_runtime/bootstrap.js",
        esm = [dir "src", "bootstrap.js"],
        options = { iroh: Iroh },
        state = move |state, options| {
            state.put::<Iroh>(options.iroh);
        },
    );

    let js_path = js_path.canonicalize()?;
    println!("Loading {}", js_path.display());

    let main_module =
        ModuleSpecifier::from_file_path(js_path).map_err(|_| anyhow::anyhow!("invalid js path"))?;
    let mut worker = MainWorker::bootstrap_from_options(
        main_module.clone(),
        PermissionsContainer::allow_all(),
        WorkerOptions {
            module_loader: Rc::new(FsModuleLoader),
            extensions: vec![iroh_runtime::init_ops_and_esm(iroh.clone())],
            bootstrap: BootstrapOptions {
                inspect: true,
                ..Default::default()
            },
            ..Default::default()
        },
    );
    worker.execute_main_module(&main_module).await?;
    worker.run_event_loop(false).await?;

    Ok(())
}

#[op2(async)]
#[serde]
async fn op_node_status(state: Rc<RefCell<OpState>>) -> Result<NodeStatusResponse, AnyError> {
    let iroh = {
        let state = state.borrow();
        state.borrow::<Iroh>().clone()
    };

    let status = iroh.node.status().await?;
    Ok(status)
}

#[op2(async)]
#[serde]
async fn op_next_doc_event(
    state: Rc<RefCell<OpState>>,
    #[smi] rid: ResourceId,
) -> Result<Option<LiveEvent>, AnyError> {
    let sub = state.borrow_mut().resource_table.get::<DocSub>(rid)?;
    let mut stream = RcRef::map(&sub, |s| &s.sub).borrow_mut().await;
    let event = stream.next().await.transpose()?;
    Ok(event)
}

#[op2(async)]
#[smi]
async fn op_doc_subscribe(state: Rc<RefCell<OpState>>) -> Result<ResourceId, AnyError> {
    let iroh = {
        let state = state.borrow();
        state.borrow::<Iroh>().clone()
    };

    // TODO: not suck
    let author = iroh.authors.create().await?;
    let doc = iroh.docs.create().await?;

    let sub = doc.subscribe().await?;
    let sub = DocSub {
        doc: doc.clone(),
        sub: AsyncRefCell::new(sub.boxed()),
    };

    // Fake data
    tokio::task::spawn(async move {
        for i in 0..10 {
            doc.set_bytes(author, format!("hello-{i}"), format!("world-{i}"))
                .await
                .ok();
        }
    });

    let rid = state.borrow_mut().resource_table.add(sub);
    Ok(rid)
}

struct DocSub {
    doc: Doc,
    sub: AsyncRefCell<BoxStream<'static, anyhow::Result<LiveEvent>>>,
}

impl Resource for DocSub {}
