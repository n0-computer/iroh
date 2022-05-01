fn main() {
    prost_build::Config::new()
        .bytes(&[".bitswap_pb.Message.Block.data"])
        .compile_protos(&["src/bitswap_pb.proto"], &["src"])
        .unwrap();
}
