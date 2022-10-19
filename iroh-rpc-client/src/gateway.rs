use std::time::{Duration, SystemTime};

// #[cfg(feature = "grpc")]
// use crate::status::{self, StatusRow};
use anyhow::Result;
use tarpc::context::Context;

impl_client!(Gateway);

const DEFAULT_DEADLINE: Duration = Duration::from_secs(60);

fn default_context() -> Context {
    let mut ctx = Context::current();
    ctx.deadline = SystemTime::now() + DEFAULT_DEADLINE;
    ctx
}

impl GatewayClient {
    pub async fn version(&self) -> Result<String> {
        let res = self.backend().await?.version(default_context()).await??;
        Ok(res)
    }
}
