pub struct IpfsSubdomain<'a> {
    pub cid_or_domain: &'a str,
    pub scheme: &'a str,
    pub hostname: &'a str,
}

impl<'a> IpfsSubdomain<'a> {
    pub(crate) fn try_from_str(value: &'a str) -> Option<Self> {
        let mut value = value.splitn(3, '.');
        if let (Some(cid_or_domain), Some(schema), Some(hostname)) =
            (value.next(), value.next(), value.next())
        {
            if schema == "ipns" || schema == "ipfs" {
                return Some(IpfsSubdomain {
                    cid_or_domain,
                    scheme: schema,
                    hostname,
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_format_try_from() {
        assert!(IpfsSubdomain::try_from_str("localhost:8080").is_none());
        assert!(IpfsSubdomain::try_from_str("localhost").is_none());
        assert!(IpfsSubdomain::try_from_str("ipfs.localhost").is_none());
        assert!(IpfsSubdomain::try_from_str("bafy.ipfs.localhost").is_some());
        assert!(IpfsSubdomain::try_from_str("ipfs-eth.ipns.localhost").is_some());
        assert!(IpfsSubdomain::try_from_str("bafy.ipfs.localhost:8080").is_some());
        assert!(IpfsSubdomain::try_from_str("bafy.ipnotfs.localhost").is_none());
        assert!(IpfsSubdomain::try_from_str("bafy.ipnotfs.localhost").is_none());

        let complex_case_1 = IpfsSubdomain::try_from_str("bafy.ipfs.bafy.ipfs.com").unwrap();
        assert_eq!(complex_case_1.cid_or_domain, "bafy");
        assert_eq!(complex_case_1.scheme, "ipfs");
        assert_eq!(complex_case_1.hostname, "bafy.ipfs.com");

        let complex_case_2 = IpfsSubdomain::try_from_str("bafy.ipfs.ipfs.com").unwrap();
        assert_eq!(complex_case_2.cid_or_domain, "bafy");
        assert_eq!(complex_case_2.scheme, "ipfs");
        assert_eq!(complex_case_2.hostname, "ipfs.com");

        let complex_case_3 = IpfsSubdomain::try_from_str("bafy.ipfs.ipns.com").unwrap();
        assert_eq!(complex_case_3.cid_or_domain, "bafy");
        assert_eq!(complex_case_3.scheme, "ipfs");
        assert_eq!(complex_case_3.hostname, "ipns.com");

        let complex_case_4 = IpfsSubdomain::try_from_str("bafy.ipns.ipfs.com").unwrap();
        assert_eq!(complex_case_4.cid_or_domain, "bafy");
        assert_eq!(complex_case_4.scheme, "ipns");
        assert_eq!(complex_case_4.hostname, "ipfs.com");

        let complex_case_5 = IpfsSubdomain::try_from_str("bafy.ipns.ipns.com").unwrap();
        assert_eq!(complex_case_5.cid_or_domain, "bafy");
        assert_eq!(complex_case_5.scheme, "ipns");
        assert_eq!(complex_case_5.hostname, "ipns.com");

        let complex_case_6 = IpfsSubdomain::try_from_str("bafy-mafy.ipfs.ipfs.com").unwrap();
        assert_eq!(complex_case_6.cid_or_domain, "bafy-mafy");
        assert_eq!(complex_case_6.scheme, "ipfs");
        assert_eq!(complex_case_6.hostname, "ipfs.com");
    }
}
