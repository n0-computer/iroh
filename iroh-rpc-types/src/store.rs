include_proto!("store");

proxy!(
    Store,
    version: () => VersionResponse => VersionResponse,
    status: () => StatusResponse => StatusResponse,
    put: PutRequest => () => (),
    get: GetRequest => GetResponse => GetResponse,
    has: HasRequest => HasResponse => HasResponse,
    get_links: GetLinksRequest => GetLinksResponse => GetLinksResponse,
    get_size: GetSizeRequest => GetSizeResponse => GetSizeResponse,
    get_block_cids: () =>
        std::pin::Pin<Box<dyn futures::Stream<Item = Result<GetBlockCidsResponse, tonic::Status>> + Send>> =>
        std::pin::Pin<Box<dyn futures::Stream<Item = anyhow::Result<GetBlockCidsResponse>> + Send>> [GetBlockCidsStream]
);
