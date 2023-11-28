use std::{cell::RefCell, path::PathBuf, rc::Rc};

use anyhow::Result;
use deno_core::{error::AnyError, op2, FsModuleLoader, ModuleSpecifier, OpState};
use deno_runtime::{
    permissions::PermissionsContainer,
    worker::{MainWorker, WorkerOptions},
    BootstrapOptions,
};

use iroh::{client::mem::Iroh, rpc_protocol::NodeStatusResponse};

pub(crate) async fn exec(iroh: &Iroh, js_path: PathBuf) -> Result<()> {
    deno_core::extension!(
        iroh_runtime,
        ops = [op_node_status],
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
