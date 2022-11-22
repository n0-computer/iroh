fn main() {
    prost_build::Config::new()
        .bytes([
            ".unixfs_pb.Data.Data",
            ".merkledag_pb.PBNode.Data",
            ".ipns_pb.IpnsEntry.Data",
        ])
        .compile_protos(
            &["src/unixfs.proto", "src/merkledag.proto", "src/ipns.proto"],
            &["src"],
        )
        .unwrap();
}
