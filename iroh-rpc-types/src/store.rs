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
