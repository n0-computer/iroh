use cid::multibase;
use cid::multibase::Base;
use iroh_resolver::resolver::{CidOrDomain, Path, PathType};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GetParams {
    /// specifies the expected format of the response
    pub format: Option<String>,
    /// specifies the desired filename of the response
    pub filename: Option<String>,
    /// specifies whether the response should be of disposition inline or attachment
    pub download: Option<bool>,
    /// specifies whether the response should render a directory even if index.html is present
    pub force_dir: Option<bool>,
    /// uri query parameter for handling navigator.registerProtocolHandler Web API requests
    pub uri: Option<String>,
    pub recursive: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DefaultHandlerPathParams {
    pub scheme: String,
    pub cid_or_domain: String,
    pub content_path: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SubdomainHandlerPathParams {
    pub content_path: Option<String>,
}

impl GetParams {
    pub fn to_query_string(&self) -> String {
        let q = serde_qs::to_string(self).unwrap();
        if q.is_empty() {
            q
        } else {
            format!("?{}", q)
        }
    }
}

pub fn recode_path_to_inlined_dns_link(path: &Path) -> String {
    match path.root() {
        CidOrDomain::Cid(cid) => match path.typ() {
            PathType::Ipfs => cid.to_string(),
            PathType::Ipns => multibase::encode(Base::Base36Lower, cid.to_bytes().as_slice()),
        },
        CidOrDomain::Domain(domain) => domain.replace('-', "--").replace('.', "-"),
    }
}

pub fn inlined_dns_link_to_dns_link(dns_link: &str) -> String {
    let dns_link = dns_link.chars().collect::<Vec<_>>();
    // first char + mapping that replaces standalone dashes + last char
    dns_link
        .iter()
        .take(1)
        .chain(
            dns_link
                .iter()
                .enumerate()
                .skip(1)
                .take(dns_link.len() - 2)
                .map(|(i, ch)| {
                    if *ch == '-' && dns_link[i - 1] != '-' && dns_link[i + 1] != '-' {
                        &'.'
                    } else {
                        ch
                    }
                })
                .chain(dns_link.iter().last()),
        )
        .collect::<String>()
        .replace("--", "-")
}

#[cfg(test)]
mod tests {
    use iroh_resolver::resolver::Path;

    use crate::handler_params::inlined_dns_link_to_dns_link;
    use crate::handler_params::recode_path_to_inlined_dns_link;

    fn just_domain(domain: &str) -> Path {
        Path::from_parts("ipns", domain, "").unwrap()
    }

    #[test]
    fn test_dns_link_to_inlined_dns_link() {
        assert_eq!(
            recode_path_to_inlined_dns_link(&just_domain("google.com")),
            "google-com",
        );
        assert_eq!(
            recode_path_to_inlined_dns_link(&just_domain("goo-gle.com")),
            "goo--gle-com",
        );
        assert_eq!(
            recode_path_to_inlined_dns_link(&just_domain("goog-l.e.com")),
            "goog--l-e-com",
        );
    }

    #[test]
    fn test_inlined_dns_link_to_dns_link() {
        assert_eq!(
            inlined_dns_link_to_dns_link(&recode_path_to_inlined_dns_link(&just_domain(
                "google.com"
            ))),
            "google.com",
        );
        assert_eq!(
            inlined_dns_link_to_dns_link(&recode_path_to_inlined_dns_link(&just_domain(
                "goo-gle.com"
            ))),
            "goo-gle.com",
        );
        assert_eq!(
            inlined_dns_link_to_dns_link(&recode_path_to_inlined_dns_link(&just_domain(
                "goog-l.e.com"
            ))),
            "goog-l.e.com",
        );
    }
}
