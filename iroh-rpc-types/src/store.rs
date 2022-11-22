include_proto!("store");

proxy!(
    Store,
    version: () => VersionResponse => VersionResponse,

    put: PutRequest => () => (),
    put_many: PutManyRequest => () => (),
    get: GetRequest => GetResponse => GetResponse,
    has: HasRequest => HasResponse => HasResponse,
    get_links: GetLinksRequest => GetLinksResponse => GetLinksResponse,
    get_size: GetSizeRequest => GetSizeResponse => GetSizeResponse
);

mod qrpc {
    use quic_rpc::{message::RpcMsg, Service};
    use bytes::Bytes;
    use cid::Cid;
    use derive_more::{From, TryInto};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug)]
    struct VersionRequest;

    #[derive(Serialize, Deserialize, Debug)]
    struct VersionResponse {
        version: String,
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct PutRequest {
        cid: Cid,
        blob: Bytes,
        links: Vec<Cid>,
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct PutManyRequest {
        blocks: Vec<PutRequest>,
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct GetRequest {
        cid: Cid,
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct GetResponse {
        data: Option<Bytes>,
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct HasRequest {
        cid: Cid,
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct HasResponse {
        has: bool,
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct GetLinksRequest {
        cid: Cid,
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct GetLinksResponse {
        links: Vec<Cid>,
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct GetSizeRequest {
        cid: Cid,
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct GetSizeResponse {
        size: Option<u64>,
    }

    #[derive(Serialize, Deserialize, Debug, From, TryInto)]
    enum StoreRequest {
        Version(VersionRequest),
        Put(PutRequest),
        PutMany(PutManyRequest),
        Get(GetRequest),
        Has(HasRequest),
        GetLinks(GetLinksRequest),
        GetSize(GetSizeRequest),
    }

    #[derive(Serialize, Deserialize, Debug, From, TryInto)]
    enum StoreResponse {
        Version(VersionResponse),
        Get(GetResponse),
        Has(HasResponse),
        GetLinks(GetLinksResponse),
        GetSize(GetSizeResponse),
        Unit(()),
    }

    #[derive(Debug, Clone, Copy)]
    struct StoreService;

    impl Service for StoreService {
        type Req = StoreRequest;

        type Res = StoreResponse;
    }

    impl RpcMsg<StoreService> for VersionRequest {
        type Response = VersionResponse;
    }

    impl RpcMsg<StoreService> for GetRequest {
        type Response = GetResponse;
    }

    impl RpcMsg<StoreService> for PutRequest {
        type Response = ();
    }

    impl RpcMsg<StoreService> for HasRequest {
      type Response = HasResponse;
  }

    impl RpcMsg<StoreService> for PutManyRequest {
        type Response = ();
    }

    impl RpcMsg<StoreService> for GetLinksRequest {
        type Response = GetLinksResponse;
    }

    impl RpcMsg<StoreService> for GetSizeRequest {
        type Response = GetSizeResponse;
    }
}
