include_proto!("gateway");

proxy!(
    Gateway,
    version: () => VersionResponse => VersionResponse
);


mod qrpc {
    use quic_rpc::{message::RpcMsg, Service};
    use derive_more::{From, TryInto};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug)]
    struct VersionRequest;

    #[derive(Serialize, Deserialize, Debug)]
    struct VersionResponse {
        version: String,
    }

    #[derive(Serialize, Deserialize, Debug, From, TryInto)]
    enum GatewayRequest {
        Version(VersionRequest),
    }

    #[derive(Serialize, Deserialize, Debug, From, TryInto)]
    enum GatewayResponse {
        Version(VersionResponse),
    }

    #[derive(Debug, Clone, Copy)]
    struct GatewayService;

    impl Service for GatewayService {
        type Req = GatewayRequest;
        type Res = GatewayResponse;
    }

    impl RpcMsg<GatewayService> for VersionRequest {
        type Response = VersionResponse;
    }
}