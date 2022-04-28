// this is just a stub for future integration with iroh-gateway
use crate::response::ResponseFormat;

#[derive(Debug, Clone, Copy)]
pub struct Client {}

impl Client {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn get_file(&self, path: &str) -> Result<String, String> {
        Ok(path.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct Request {
    pub format: ResponseFormat,
    pub cid: String,
    pub full_content_path: String,
    pub query_file_name: String,
    pub content_path: String,
    pub download: bool,
}
