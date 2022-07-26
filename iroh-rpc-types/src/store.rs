include_proto!("store");

proxy!(
    Store,
    version: () => VersionResponse,
    put: PutRequest => (),
    get: GetRequest => GetResponse,
    has: HasRequest => HasResponse,
    get_links: GetLinksRequest => GetLinksResponse
);
