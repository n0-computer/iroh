use crate::{constants::*, response::ResponseFormat};
use ::time::OffsetDateTime;
use axum::http::header::*;
use iroh_resolver::resolver::{CidOrDomain, Metadata, PathType};
use std::{fmt::Write, time};

#[tracing::instrument()]
pub fn add_user_headers(headers: &mut HeaderMap, user_headers: HeaderMap) {
    headers.extend(user_headers.into_iter());
}

#[tracing::instrument()]
pub fn add_content_type_headers(headers: &mut HeaderMap, name: &str) {
    let guess = mime_guess::from_path(name);
    let content_type = guess.first_or_octet_stream().to_string();
    // todo(arqu): deeper content type checking
    // todo(arqu): if mime type starts with text/html; strip encoding to let browser detect
    headers.insert(CONTENT_TYPE, HeaderValue::from_str(&content_type).unwrap());
}

#[tracing::instrument()]
pub fn add_content_disposition_headers(
    headers: &mut HeaderMap,
    filename: &str,
    content_path: &str,
    should_download: bool,
) -> String {
    let mut name = get_filename(content_path);
    if !filename.is_empty() {
        name = filename.to_string();
    }
    if !name.is_empty() {
        let disposition = if should_download {
            DISPOSITION_ATTACHMENT
        } else {
            DISPOSITION_INLINE
        };
        set_content_disposition_headers(headers, &name, disposition);
    }
    name
}

#[tracing::instrument()]
pub fn set_content_disposition_headers(headers: &mut HeaderMap, filename: &str, disposition: &str) {
    headers.insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("{}; filename={}", disposition, filename)).unwrap(),
    );
}

#[tracing::instrument()]
pub fn add_cache_control_headers(headers: &mut HeaderMap, metadata: Metadata) {
    if metadata.path.typ() == PathType::Ipns {
        let lmdt: OffsetDateTime = time::SystemTime::now().into();
        headers.insert(
            LAST_MODIFIED,
            HeaderValue::from_str(&lmdt.to_string()).unwrap(),
        );
    } else {
        headers.insert(LAST_MODIFIED, HeaderValue::from_str("0").unwrap());
        headers.insert(CACHE_CONTROL, VAL_IMMUTABLE_MAX_AGE.clone());
    }
}

#[tracing::instrument()]
pub fn add_ipfs_roots_headers(headers: &mut HeaderMap, metadata: Metadata) {
    let mut roots = "".to_string();
    for (_path, rcid) in metadata.resolved_path {
        write!(roots, "{},", rcid).unwrap();
    }
    roots.pop();
    headers.insert(&HEADER_X_IPFS_ROOTS, HeaderValue::from_str(&roots).unwrap());
}

#[tracing::instrument()]
pub fn set_etag_headers(headers: &mut HeaderMap, etag: String) {
    headers.insert(ETAG, HeaderValue::from_str(&etag).unwrap());
}

#[tracing::instrument()]
pub fn get_etag(cid: &CidOrDomain, response_format: Option<ResponseFormat>) -> String {
    match cid {
        CidOrDomain::Cid(cid) => {
            let mut suffix = "".to_string();
            if let Some(fmt) = response_format {
                let ext = fmt.get_extenstion();
                if !ext.is_empty() {
                    suffix = format!(".{}", ext);
                }
            }
            format!("\"{}{}\"", cid, suffix)
        }
        CidOrDomain::Domain(_) => {
            // TODO:
            String::new()
        }
    }
}

#[tracing::instrument()]
pub fn etag_matches(inm: &str, cid_etag: &str) -> bool {
    let mut buf = inm.trim();
    loop {
        if buf.is_empty() {
            break;
        }
        if buf.starts_with(',') {
            buf = &buf[1..];
            continue;
        }
        if buf.starts_with('*') {
            return true;
        }
        let (etag, remain) = scan_etag(buf);
        if etag.is_empty() {
            break;
        }
        if etag_weak_match(etag, cid_etag) {
            return true;
        }
        buf = remain;
    }
    false
}

#[tracing::instrument()]
pub fn scan_etag(buf: &str) -> (&str, &str) {
    let s = buf.trim();
    let mut start = 0;
    if s.starts_with("W/") {
        start = 2;
    }
    if s.len() - start < 2 || s.chars().nth(start) != Some('"') {
        return ("", "");
    }
    for i in start + 1..s.len() {
        let c = s.as_bytes().get(i).unwrap();
        if *c == 0x21 || (0x23..0x7E).contains(c) || *c >= 0x80 {
            continue;
        }
        if *c == b'"' {
            return (&s[..i + 1], &s[i + 1..]);
        }
        return ("", "");
    }
    ("", "")
}

#[tracing::instrument()]
pub fn etag_weak_match(etag: &str, cid_etag: &str) -> bool {
    etag.trim_start_matches("W/") == cid_etag.trim_start_matches("W/")
}

#[tracing::instrument()]
pub fn get_filename(content_path: &str) -> String {
    content_path
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .last()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use cid::Cid;

    use super::*;

    #[test]
    fn add_user_headers_test() {
        let mut headers = HeaderMap::new();
        let mut user_headers = HeaderMap::new();
        user_headers.insert(
            &HEADER_X_IPFS_PATH,
            HeaderValue::from_str("QmHeaderPath1").unwrap(),
        );
        user_headers.insert(
            &HEADER_X_IPFS_PATH,
            HeaderValue::from_str("QmHeaderPath2").unwrap(),
        );
        add_user_headers(&mut headers, user_headers);
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers.get(&HEADER_X_IPFS_PATH).unwrap(),
            &"QmHeaderPath2".to_string()
        );
    }

    #[test]
    fn add_content_type_headers_test() {
        let mut headers = HeaderMap::new();
        let name = "test.txt";
        add_content_type_headers(&mut headers, name);
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers.get(&CONTENT_TYPE).unwrap(),
            &"text/plain".to_string()
        );

        let mut headers = HeaderMap::new();
        let name = "test.RAND_EXT";
        add_content_type_headers(&mut headers, name);
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers.get(&CONTENT_TYPE).unwrap(),
            &CONTENT_TYPE_OCTET_STREAM
        );
    }

    #[test]
    fn add_content_disposition_headers_test() {
        // inline
        let mut headers = HeaderMap::new();
        let filename = "test.txt";
        let content_path = "QmSomeCid";
        let download = false;
        let name = add_content_disposition_headers(&mut headers, filename, content_path, download);
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers.get(&CONTENT_DISPOSITION).unwrap(),
            &"inline; filename=test.txt".to_string()
        );
        assert_eq!(name, "test.txt");

        // attachment
        let mut headers = HeaderMap::new();
        let filename = "test.txt";
        let content_path = "QmSomeCid";
        let download = true;
        let name = add_content_disposition_headers(&mut headers, filename, content_path, download);
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers.get(&CONTENT_DISPOSITION).unwrap(),
            &"attachment; filename=test.txt".to_string()
        );
        assert_eq!(name, "test.txt");

        // no filename & no content path filename
        let mut headers = HeaderMap::new();
        let filename = "";
        let content_path = "QmSomeCid";
        let download = true;
        let name = add_content_disposition_headers(&mut headers, filename, content_path, download);
        assert_eq!(headers.len(), 1);
        assert_eq!(name, "QmSomeCid");

        // no filename & with content path filename
        let mut headers = HeaderMap::new();
        let filename = "";
        let content_path = "QmSomeCid/folder/test.txt";
        let download = true;
        let name = add_content_disposition_headers(&mut headers, filename, content_path, download);
        assert_eq!(headers.len(), 1);
        assert_eq!(name, "test.txt");
    }

    #[test]
    fn set_content_disposition_headers_test() {
        let mut headers = HeaderMap::new();
        let filename = "test_inline.txt";
        set_content_disposition_headers(&mut headers, filename, DISPOSITION_INLINE);
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers.get(&CONTENT_DISPOSITION).unwrap(),
            &"inline; filename=test_inline.txt".to_string()
        );

        let mut headers = HeaderMap::new();
        let filename = "test_attachment.txt";
        set_content_disposition_headers(&mut headers, filename, DISPOSITION_ATTACHMENT);
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers.get(&CONTENT_DISPOSITION).unwrap(),
            &"attachment; filename=test_attachment.txt".to_string()
        );
    }

    #[test]
    fn get_filename_test() {
        assert_eq!(get_filename("QmSomeCid/folder/test.txt"), "test.txt");
        assert_eq!(get_filename("QmSomeCid/folder"), "folder");
        assert_eq!(get_filename("QmSomeCid"), "QmSomeCid");
        assert_eq!(get_filename(""), "");
    }

    #[test]
    fn etag_test() {
        let any_etag = "*";
        let etag = get_etag(
            &CidOrDomain::Cid(
                Cid::try_from("bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy")
                    .unwrap(),
            ),
            Some(ResponseFormat::Raw),
        );
        let wetag = format!("W/{}", etag);
        let other_etag = get_etag(
            &CidOrDomain::Cid(
                Cid::try_from("bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4aaaaa")
                    .unwrap(),
            ),
            Some(ResponseFormat::Raw),
        );
        let other_wetag = format!("W/{}", other_etag);
        let long_etag = format!("{},{}", other_etag, wetag);

        assert!(etag_matches(any_etag, &etag));
        assert!(etag_matches(&etag, &wetag));
        assert!(etag_matches(&long_etag, &etag));
        assert!(!etag_matches(&etag, &other_wetag));
    }
}
