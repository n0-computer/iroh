fn main() {
    let mut config = prost_build::Config::new();
    config.bytes(&[".p2p.BitswapResponse"]);

    tonic_build::configure()
        .compile_with_config(config, &["proto/p2p.proto"], &["proto"])
        .unwrap();
}
