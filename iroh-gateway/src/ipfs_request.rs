use crate::handler_params::GetParams;
use crate::response::ResponseFormat;
use iroh_resolver::resolver::{CidOrDomain, Out};

#[derive(Debug)]
pub struct IpfsRequest {
    pub format: ResponseFormat,
    pub cid: CidOrDomain,
    pub resolved_path: iroh_resolver::resolver::Path,
    pub query_params: GetParams,
    pub subdomain_mode: bool,
    pub path_metadata: Out,
}

impl IpfsRequest {
    pub fn request_path_for_redirection(&self) -> String {
        if self.subdomain_mode {
            self.resolved_path.to_relative_string()
        } else {
            self.resolved_path.to_string()
        }
    }

    pub fn query_file_name(&self) -> &str {
        self.query_params.filename.as_deref().unwrap_or_default()
    }

    pub fn query_download(&self) -> bool {
        self.query_params.download.unwrap_or_default()
    }
}
