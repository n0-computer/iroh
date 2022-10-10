fn main() {
    let mut config = prost_build::Config::new();
    config.bytes(&[
        ".p2p.BitswapBlock.data",
        ".p2p.BitswapResponse",
        ".p2p.GossipsubPublishRequest.data",
        ".store.PutRequest.blob",
        ".store.GetResponse.data",
    ]);

    let source_files = [
        "proto/p2p.proto",
        "proto/store.proto",
        "proto/gateway.proto",
        "proto/test.proto",
    ];
    let source_dirs = ["proto"];

    #[cfg(feature = "grpc")]
    tonic_build::configure()
        .compile_with_config(config, &source_files, &source_dirs)
        .unwrap();
    #[cfg(not(feature = "grpc"))]
    config.compile_protos(&source_files, &source_dirs).unwrap();
}
