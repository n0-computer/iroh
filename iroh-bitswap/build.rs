fn main() {
    prost_build::Config::new()
        .bytes([
            ".bitswap_pb.Message.Block.data",
            ".bitswap_pb.Message.blocks",
        ])
        .compile_protos(&["src/bitswap_pb.proto"], &["src"])
        .unwrap();
}
