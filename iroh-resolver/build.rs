fn main() {
    prost_build::Config::new()
        .bytes([".unixfs_pb.Data", ".merkledag_pb.PBNode.Data"])
        .compile_protos(&["src/unixfs.proto", "src/merkledag.proto"], &["src"])
        .unwrap();
}
