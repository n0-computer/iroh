use crate::RpcError;

#[tarpc::service]
pub trait Gateway {
    async fn version() -> Result<String, RpcError>;
}
