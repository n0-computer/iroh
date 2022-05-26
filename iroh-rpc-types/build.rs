fn main() {
    let mut config = prost_build::Config::new();
    config.bytes(&[
        ".p2p.BitswapResponse",
        ".store.PutRequest.blob",
        ".store.GetResponse.data",
    ]);

    tonic_build::configure()
        .compile_with_config(
            config,
            &[
                "proto/p2p.proto",
                "proto/store.proto",
                "proto/gateway.proto",
            ],
            &["proto"],
        )
        .unwrap();
}
