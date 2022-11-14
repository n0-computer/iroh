use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),

    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    #[error(transparent)]
    RpcClient(#[from] iroh_rpc_client::Error),

    #[error(transparent)]
    Cid(#[from] cid::Error),

    #[error(transparent)]
    ProstDecode(#[from] prost::DecodeError),

    #[error(transparent)]
    DataTypeNumFromPrimitive(#[from] num_enum::TryFromPrimitiveError<crate::unixfs::DataType>),

    #[error(transparent)]
    CodecNumFromPrimitive(#[from] num_enum::TryFromPrimitiveError<crate::codecs::Codec>),

    #[error(transparent)]
    Ipld(#[from] libipld::error::Error),

    #[error(transparent)]
    IpldInvalidMultiHash(#[from] libipld::error::InvalidMultihash),

    #[error(transparent)]
    IpldUnsupportedMultihash(#[from] libipld::error::UnsupportedMultihash),

    #[error(transparent)]
    IpldUnsupportedCodec(#[from] libipld::error::UnsupportedCodec),

    #[error(transparent)]
    DnsResolver(#[from] trust_dns_resolver::error::ResolveError),

    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    #[error(transparent)]
    TokioJoin(#[from] tokio::task::JoinError),

    #[error(transparent)]
    Url(#[from] url::ParseError),

    #[error("provided path was not a file: {}", .0.display())]
    PathNotFile(PathBuf),

    #[error("provided path was not a directory: {}", .0.display())]
    PathNotDirectory(PathBuf),

    #[error("provided path was not a symlink: {}", .0.display())]
    PathNotSymlink(PathBuf),

    #[error("directory entry is neither file nor directory")]
    DirEntryNotFileOrDirectory,

    #[error("node is too large: {} bytes", .0)]
    NodeTooLarge(usize),

    #[error("Bitfield is too large: {}", .0)]
    BitfieldTooLarge(usize),

    #[error("invalid hash bit length")]
    InvalidHashBitLength,

    #[error("target path {} is not valid unicode", .0.display())]
    PathNotUnicode(PathBuf),

    #[error("must add a name when building a file from a reader or bytes")]
    MissingNameForFile,

    #[error("must have a path to the content or a reader for the content")]
    MissingPathToContent,

    #[error("Missing link")]
    MissingLink,

    #[error("Missing data")]
    MissingData,

    #[error("too many links to fit into one chunk, must be encoded as a HAMT. However, HAMT creation has not yet been implemented.")]
    TooManyLinksForChunk,

    #[error("unixfs metadata is not supported")]
    UnixFsMetadataUnsupported,

    #[error("Unsupported Codec {:?}", .0)]
    UnsupportedCodec(crate::codecs::Codec),

    #[error("UnixfsNode::Directory link '{}' not found", .0)]
    UnixFSNodeDirectoryLinkNotFound(String),

    #[error("unexpected unixfs type {:?}", .0)]
    UnexpectedUnixFsType(Option<crate::unixfs::DataType>),

    #[error("UnixfsNode::HamtShard link '{}' not found", .0)]
    HamtShardLinkNotFound(String),

    #[error("Expected the DagPb node to have a list of links.")]
    ExpectedDagPbToHaveLinks,

    #[error("expected DagPb links to exist")]
    ExpectedDagPbLinksToExist,

    #[error("Expected the Dagpb link to have a '{}' field", .0)]
    ExpectedDagPbLinkToHaveField(&'static str),

    #[error("expected DagPb link to have a string Name field")]
    ExpectedDagPbLinkToHaveStringNameField,

    #[error("could not find DagPb link '{}'", .0)]
    CouldNotFindDagPbLink(String),

    #[error("invalid domain encountered")]
    InvalidDomain,

    #[error("no valid dnslink records found for {}", .0)]
    NoValidDnsLinkRecords(String),

    #[error("cannot resolve {}, too many recursive lookups", .0)]
    TooManyRecursiveLookups(String),

    #[error("path too short")]
    PathTooShort,

    #[error("max depth reached")]
    MaxDepthReached,

    #[error("hamt: only murmur3 is supported")]
    HamtOnlyMurmur3,

    #[error("fanout must be non zero")]
    FanoutMustBeNonZero,

    #[error("unexpected node: {:?}", .0)]
    UnexpectedNode(crate::resolver::OutType),

    #[error("Failed to find: {:?}", .0)]
    FailedToFind(cid::Cid),

    #[error("Number of links exceeds the recursion limit.")]
    LinkNumExceedsRecursionLimit,

    #[error("links do not match")]
    LinksNotMatch,

    #[error("IPLD resolve error: Couldn't find part {} in path '{}'", .0, .1.join("/"))]
    IPLDResolveError(String, Vec<String>),

    #[error("cannot read the contents of a directory")]
    CannotReadDirContents,
}
