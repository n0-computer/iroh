include_proto!("gateway");

proxy!(Gateway,
(
    Gateway,
    version: () => VersionResponse
)
);
