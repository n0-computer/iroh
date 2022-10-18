include_proto!("gateway");

proxy!(
    Gateway,
    version: () => VersionResponse => VersionResponse
);
