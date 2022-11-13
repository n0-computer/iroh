include_proto!("gateway");

proxy!(
    Gateway,
    crate::error::Error,
    version: () => VersionResponse => VersionResponse
);
