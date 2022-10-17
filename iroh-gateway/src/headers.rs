use crate::{constants::*, response::ResponseFormat};
use ::time::OffsetDateTime;
use axum::http::header::*;
use iroh_resolver::resolver::{CidOrDomain, Metadata, PathType};
use mime::Mime;
use once_cell::sync::Lazy;
use sha2::Digest;
use std::{fmt::Write, ops::Range, time};

#[tracing::instrument()]
pub fn add_user_headers(headers: &mut HeaderMap, user_headers: HeaderMap) {
    headers.extend(user_headers.into_iter());
}

#[tracing::instrument()]
pub fn add_content_type_headers(
    headers: &mut HeaderMap,
    name: &str,
    content_sniffed_mime: Option<Mime>,
) {
    let guess = mime_guess::from_path(name);
    let mut content_type = String::new();
    if let Some(ct) = guess.first() {
        content_type = ct.to_string();
    } else if let Some(ct) = content_sniffed_mime {
        content_type = ct.to_string();
    }

    // for most text types we want to add charset=utf-8
    if content_type.starts_with("text/") && !content_type.contains("charset") {
        content_type.push_str("; charset=utf-8");
    }

    // for html we want to explicitly have the browser detect encoding
    if content_type.starts_with("text/html") {
        content_type = "text/html".to_string()
    }

    if !content_type.is_empty() {
        headers.insert(CONTENT_TYPE, HeaderValue::from_str(&content_type).unwrap());
    }
}

#[tracing::instrument()]
pub fn add_content_disposition_headers(
    headers: &mut HeaderMap,
    filename: &str,
    content_path: &iroh_resolver::resolver::Path,
    should_download: bool,
) -> String {
    let mut name = get_filename(&content_path.to_string());
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
    // TODO: handle non-ascii filenames https://github.com/ipfs/specs/blob/main/http-gateways/PATH_GATEWAY.md#content-disposition-response-header
    headers.insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("{}; filename={}", disposition, filename)).unwrap(),
    );
}

#[tracing::instrument()]
pub fn add_content_range_headers(headers: &mut HeaderMap, range: Range<u64>, size: Option<u64>) {
    if range.end == 0 {
        // this should never happen as it is checked for in parse_range_header
        // but just to avoid any footguns
        return;
    }
    let content_range = if let Some(size) = size {
        format!("bytes {}-{}/{}", range.start, range.end - 1, size)
    } else {
        format!("bytes {}-{}/{}", range.start, range.end - 1, "*")
    };
    headers.insert(
        CONTENT_RANGE,
        HeaderValue::from_str(&content_range).unwrap(),
    );
}

pub fn parse_range_header(range: &HeaderValue) -> Option<Range<u64>> {
    // TODO: potentially support multiple ranges ie bytes=0-100,200-300
    let range = range.to_str().ok()?;
    let mut parts = range.splitn(2, '=');
    if parts.next() != Some("bytes") {
        return None;
    }
    let mut range = parts.next()?.splitn(2, '-');
    let start = range.next()?.parse().ok()?;
    let end = range.next()?.parse().ok()?;
    if start >= end || end == 0 {
        return None;
    }
    Some(Range { start, end })
}

#[tracing::instrument()]
pub fn add_cache_control_headers(headers: &mut HeaderMap, metadata: Metadata) {
    if metadata.path.typ() == PathType::Ipns {
        let lmdt: OffsetDateTime = time::SystemTime::now().into();
        // TODO: better last modified headers based on actual dns ttls
        headers.insert(
            LAST_MODIFIED,
            HeaderValue::from_str(&lmdt.to_string()).unwrap(),
        );
    } else {
        headers.insert(CACHE_CONTROL, VAL_IMMUTABLE_MAX_AGE.clone());
    }
}

#[tracing::instrument()]
pub fn add_content_length_header(headers: &mut HeaderMap, metadata: Metadata) {
    if let Some(size) = metadata.size {
        headers.insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&size.to_string()).unwrap(),
        );
    }
}

#[tracing::instrument()]
pub fn add_ipfs_roots_headers(headers: &mut HeaderMap, metadata: Metadata) {
    let mut roots = "".to_string();
    for rcid in metadata.resolved_path {
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
pub fn add_etag_range(headers: &mut HeaderMap, range: Range<u64>) {
    if headers.contains_key(ETAG) {
        let etag = headers.get(ETAG).unwrap().to_str().unwrap();
        let etag = etag.trim_end_matches('"');
        let etag = format!("{}.{}-{}\"", etag, range.start, range.end - 1);
        headers.insert(ETAG, HeaderValue::from_str(&etag).unwrap());
    }
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
pub fn get_dir_etag(cid: &CidOrDomain) -> String {
    match cid {
        CidOrDomain::Cid(cid) => {
            format!("\"Dir-{}-CID-{}\"", *VERSION_TEMPLATE_HASH, cid)
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

pub fn version_and_template_hash() -> String {
    let v = format!(
        "{}-{}-{}-{}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        crate::templates::DIR_LIST_TEMPLATE,
        crate::templates::NOT_FOUND_TEMPLATE,
    );
    let mut hasher = sha2::Sha256::new();
    hasher.update(v.as_bytes());
    let hash = hasher.finalize();
    hex::encode(hash)
}

pub(crate) static VERSION_TEMPLATE_HASH: Lazy<String> = Lazy::new(version_and_template_hash);

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
        let body = "test body";
        let content_sniffed_mime = Some(crate::client::sniff_content_type(body.as_bytes()));
        add_content_type_headers(&mut headers, name, content_sniffed_mime.clone());
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers.get(&CONTENT_TYPE).unwrap(),
            &"text/plain; charset=utf-8".to_string()
        );

        let mut headers = HeaderMap::new();
        let name = "test.RAND_EXT";
        add_content_type_headers(&mut headers, name, content_sniffed_mime);
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers.get(&CONTENT_TYPE).unwrap(),
            &"text/plain; charset=utf-8".to_string()
        );
    }

    #[test]
    fn parse_range_header_test() {
        let range = HeaderValue::from_str("bytes=0-10").unwrap();
        let r = parse_range_header(&range);
        assert_eq!(r, Some(Range { start: 0, end: 10 }));

        let range = HeaderValue::from_str("byts=0-10").unwrap();
        let r = parse_range_header(&range);
        assert_eq!(r, None);

        let range = HeaderValue::from_str("bytes=0-").unwrap();
        let r = parse_range_header(&range);
        assert_eq!(r, None);

        let range = HeaderValue::from_str("bytes=10-1").unwrap();
        let r = parse_range_header(&range);
        assert_eq!(r, None);

        let range = HeaderValue::from_str("bytes=0-0").unwrap();
        let r = parse_range_header(&range);
        assert_eq!(r, None);

        let range = HeaderValue::from_str("bytes=100-200").unwrap();
        let r = parse_range_header(&range);
        assert_eq!(
            r,
            Some(Range {
                start: 100,
                end: 200
            })
        );

        let range = HeaderValue::from_str("bytes=0-10,20-30").unwrap();
        let r = parse_range_header(&range);
        assert_eq!(r, None);
    }

    #[test]
    fn add_content_disposition_headers_test() {
        // inline
        let mut headers = HeaderMap::new();
        let filename = "test.txt";
        let content_path: iroh_resolver::resolver::Path =
            "/ipfs/bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy"
                .parse()
                .unwrap();
        let download = false;
        let name = add_content_disposition_headers(&mut headers, filename, &content_path, download);
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers.get(&CONTENT_DISPOSITION).unwrap(),
            &"inline; filename=test.txt".to_string()
        );
        assert_eq!(name, "test.txt");

        // attachment
        let mut headers = HeaderMap::new();
        let filename = "test.txt";
        let content_path: iroh_resolver::resolver::Path =
            "/ipfs/bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy"
                .parse()
                .unwrap();
        let download = true;
        let name = add_content_disposition_headers(&mut headers, filename, &content_path, download);
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers.get(&CONTENT_DISPOSITION).unwrap(),
            &"attachment; filename=test.txt".to_string()
        );
        assert_eq!(name, "test.txt");

        // no filename & no content path filename
        let mut headers = HeaderMap::new();
        let filename = "";
        let content_path: iroh_resolver::resolver::Path =
            "/ipfs/bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy"
                .parse()
                .unwrap();
        let download = true;
        let name = add_content_disposition_headers(&mut headers, filename, &content_path, download);
        assert_eq!(headers.len(), 1);
        assert_eq!(
            name,
            "bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy"
        );

        // no filename & with content path filename
        let mut headers = HeaderMap::new();
        let filename = "";
        let content_path: iroh_resolver::resolver::Path =
            "/ipfs/bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy/folder/test.txt"
                .parse()
                .unwrap();
        let download = true;
        let name = add_content_disposition_headers(&mut headers, filename, &content_path, download);
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
