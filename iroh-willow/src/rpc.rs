pub mod client;
pub mod handler;
pub mod proto;

type RpcClient<C = quic_rpc::client::BoxedConnector<proto::RpcService>> =
    quic_rpc::RpcClient<proto::RpcService, C>;
