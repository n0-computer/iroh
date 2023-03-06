use crate::hp::key;

#[derive(Debug)]
pub struct Server {}

impl Server {
    pub fn new(key: key::node::SecretKey) -> Self {
        // TODO:
        Server {}
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ServerInfo {
    pub(crate) version: usize,
    pub(crate) token_bucket_bytes_per_second: usize,
    pub(crate) token_bucket_bytes_burst: usize,
}
