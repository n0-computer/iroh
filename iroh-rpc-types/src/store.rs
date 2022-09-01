include_proto!("store");

proxy!(
    Store,
    version: () => VersionResponse => VersionResponse,
    put: PutRequest => () => (),
    get: GetRequest => GetResponse => GetResponse,
    has: HasRequest => HasResponse => HasResponse,
    get_links: GetLinksRequest => GetLinksResponse => GetLinksResponse
);
