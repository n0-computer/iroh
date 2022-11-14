use std::path::PathBuf;

/// LockError is the set of known program lock errors
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("Can't connect to {service}. Is the service running?")]
    ConnectionRefused { service: &'static str },

    #[error(transparent)]
    Util(#[from] iroh_util::UtilError),

    #[error(transparent)]
    RpcClient(#[from] iroh_rpc_client::Error),

    #[error(transparent)]
    RpcTypes(#[from] iroh_rpc_types::error::Error),

    #[error(transparent)]
    Resolver(#[from] iroh_resolver::error::Error),

    #[error(transparent)]
    RelativePath(#[from] relative_path::FromPathError),

    #[error(transparent)]
    UrlParse(#[from] url::ParseError),

    #[error("IPFS path does not refer to a CID")]
    PathNotCid,

    #[error("can only add files or directories")]
    CanOnlyAddFilesOrDirs,

    #[error("No cid found")]
    NoCidFound,

    #[error("output path {} already exists", .0.display())]
    OutputPathExists(PathBuf),

    #[error("Multiaddress contains invalid p2p multihash {:?}. Cannot derive a PeerId from this address.", .0)]
    MultiaddrInvalidP2pMultiHash(cid::multihash::Multihash),

    #[error("Mulitaddress must include the peer id")]
    MultiaddrMustIncludePeerId,
}

pub fn map_service_error(service: &'static str, e: iroh_rpc_client::Error) -> Error {
    match e {
        iroh_rpc_client::Error::MissingP2pConn
        | iroh_rpc_client::Error::MissingRpcGatewayConn
        | iroh_rpc_client::Error::MissingRpcStoreConn => Error::ConnectionRefused { service },
        _ => Error::RpcClient(e),
    }
}
