use std::net::{IpAddr, SocketAddr};

pub use stun_rs::{
    attributes::StunAttribute, error::StunDecodeError, methods, MessageClass, MessageDecoder,
    TransactionId,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Parse(#[from] StunDecodeError),
    #[error("not binding")]
    NotBinding,
    #[error("not success response")]
    NotSuccessResponse,
    #[error("malformed attributes")]
    MalformedAttrs,
    #[error("no fingerprint")]
    NoFingerprint,
    #[error("invalid fingerprint")]
    InvalidFingerprint,
}

/// Parses a STUN binding request.
pub fn parse_binding_request(b: &[u8]) -> Result<TransactionId, Error> {
    let decoder = MessageDecoder::default();
    let (msg, _) = decoder.decode(b)?;

    let tx = *msg.transaction_id();
    if msg.method() != methods::BINDING {
        return Err(Error::NotBinding);
    }

    // TODO: Tailscale sets the software to tailscale, we should check if we want to do this too.

    let mut got_fp = None;

    let attrs = msg.attributes();
    let attrs_len = attrs.len();
    for (i, attr) in attrs.iter().enumerate() {
        match attr {
            StunAttribute::Fingerprint(fp) => {
                // must be last
                if i != attrs_len - 1 {
                    return Err(Error::NoFingerprint);
                }
                got_fp = Some(fp);
            }
            _ => {}
        }
    }

    let fp = got_fp.ok_or_else(|| Error::NoFingerprint)?;
    const FINGERPRINT_SIZE: usize = 4;
    if !fp.validate(&b[..b.len() - FINGERPRINT_SIZE]) {
        return Err(Error::InvalidFingerprint);
    }

    Ok(tx)
}

/// Parses a successful binding response STUN packet.
/// The IP address is extracted from the XOR-MAPPED-ADDRESS attribute.
pub fn parse_response(b: &[u8]) -> Result<(TransactionId, SocketAddr), Error> {
    let decoder = MessageDecoder::default();
    let (msg, _) = decoder.decode(b)?;

    let tx = *msg.transaction_id();
    if msg.class() != MessageClass::SuccessResponse {
        return Err(Error::NotSuccessResponse);
    }

    // Read through the attributes.
    // The the addr+port reported by XOR-MAPPED-ADDRESS
    // as the canonical value. If the attribute is not
    // present but the STUN server responds with
    // MAPPED-ADDRESS we fall back to it.

    let mut addr = None;
    let mut fallback_addr = None;
    for attr in msg.attributes() {
        match attr {
            StunAttribute::XorMappedAddress(a) => {
                let mut a = *a.socket_address();
                a.set_ip(to_canonical(a.ip()));
                addr = Some(a);
            }
            StunAttribute::MappedAddress(a) => {
                let mut a = *a.socket_address();
                a.set_ip(to_canonical(a.ip()));
                fallback_addr = Some(a);
            }
            _ => {}
        }
    }

    if let Some(addr) = addr {
        return Ok((tx, addr));
    }

    if let Some(addr) = fallback_addr {
        return Ok((tx, addr));
    }

    Err(Error::MalformedAttrs)
}

// TODO: replace with IpAddr::to_canoncial once stabilized.
pub fn to_canonical(ip: IpAddr) -> IpAddr {
    match ip {
        ip @ IpAddr::V4(_) => ip,
        IpAddr::V6(ip) => {
            if let Some(ip) = ip.to_ipv4_mapped() {
                IpAddr::V4(ip)
            } else {
                IpAddr::V6(ip)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    struct ResponseTestCase {
        name: &'static str,
        data: Vec<u8>,
        want_tid: Vec<u8>,
        want_addr: IpAddr,
        want_port: u16,
    }

    #[test]
    fn test_parse_response() {
        let cases = vec![
            ResponseTestCase {
		name: "google-1",
		data: vec![
		    0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42,
		    0x23, 0x60, 0xb1, 0x1e, 0x3e, 0xc6, 0x8f, 0xfa,
		    0x93, 0xe0, 0x80, 0x07, 0x00, 0x20, 0x00, 0x08,
		    0x00, 0x01, 0xc7, 0x86, 0x69, 0x57, 0x85, 0x6f,
		],
		want_tid: vec![
		    0x23, 0x60, 0xb1, 0x1e, 0x3e, 0xc6, 0x8f, 0xfa,
		    0x93, 0xe0, 0x80, 0x07,
		],
		want_addr: IpAddr::V4(Ipv4Addr::from([72, 69, 33, 45])),
		want_port: 59028,
	    },
	    ResponseTestCase {
		name: "google-2",
		data: vec![
		    0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42,
		    0xf9, 0xf1, 0x21, 0xcb, 0xde, 0x7d, 0x7c, 0x75,
		    0x92, 0x3c, 0xe2, 0x71, 0x00, 0x20, 0x00, 0x08,
		    0x00, 0x01, 0xc7, 0x87, 0x69, 0x57, 0x85, 0x6f,
		],
		want_tid: vec![
		    0xf9, 0xf1, 0x21, 0xcb, 0xde, 0x7d, 0x7c, 0x75,
		    0x92, 0x3c, 0xe2, 0x71,
		],
		want_addr: IpAddr::V4(Ipv4Addr::from([72, 69, 33, 45])),
		want_port: 59029,
	    },
	    ResponseTestCase{
		name: "stun.sipgate.net:10000",
		data: vec![
		    0x01, 0x01, 0x00, 0x44, 0x21, 0x12, 0xa4, 0x42,
		    0x48, 0x2e, 0xb6, 0x47, 0x15, 0xe8, 0xb2, 0x8e,
		    0xae, 0xad, 0x64, 0x44, 0x00, 0x01, 0x00, 0x08,
		    0x00, 0x01, 0xe4, 0xab, 0x48, 0x45, 0x21, 0x2d,
		    0x00, 0x04, 0x00, 0x08, 0x00, 0x01, 0x27, 0x10,
		    0xd9, 0x0a, 0x44, 0x98, 0x00, 0x05, 0x00, 0x08,
		    0x00, 0x01, 0x27, 0x11, 0xd9, 0x74, 0x7a, 0x8a,
		    0x80, 0x20, 0x00, 0x08, 0x00, 0x01, 0xc5, 0xb9,
		    0x69, 0x57, 0x85, 0x6f, 0x80, 0x22, 0x00, 0x10,
		    0x56, 0x6f, 0x76, 0x69, 0x64, 0x61, 0x2e, 0x6f,
		    0x72, 0x67, 0x20, 0x30, 0x2e, 0x39, 0x36, 0x00,
		],
		want_tid: vec![
		    0x48, 0x2e, 0xb6, 0x47, 0x15, 0xe8, 0xb2, 0x8e,
		    0xae, 0xad, 0x64, 0x44,
		],
		want_addr: IpAddr::V4(Ipv4Addr::from([72, 69, 33, 45])),
		want_port: 58539,
	    },
	    ResponseTestCase{
		name: "stun.powervoip.com:3478",
		data: vec![
		    0x01, 0x01, 0x00, 0x24, 0x21, 0x12, 0xa4, 0x42,
		    0x7e, 0x57, 0x96, 0x68, 0x29, 0xf4, 0x44, 0x60,
		    0x9d, 0x1d, 0xea, 0xa6, 0x00, 0x01, 0x00, 0x08,
		    0x00, 0x01, 0xe9, 0xd3, 0x48, 0x45, 0x21, 0x2d,
		    0x00, 0x04, 0x00, 0x08, 0x00, 0x01, 0x0d, 0x96,
		    0x4d, 0x48, 0xa9, 0xd4, 0x00, 0x05, 0x00, 0x08,
		    0x00, 0x01, 0x0d, 0x97, 0x4d, 0x48, 0xa9, 0xd5,
		],
		want_tid: vec![
		    0x7e, 0x57, 0x96, 0x68, 0x29, 0xf4, 0x44, 0x60,
		    0x9d, 0x1d, 0xea, 0xa6,
		],
		want_addr: IpAddr::V4(Ipv4Addr::from([72, 69, 33, 45])),
		want_port: 59859,
	    },
	    ResponseTestCase{
		name: "in-process pion server",
		data: vec![
		    0x01, 0x01, 0x00, 0x24, 0x21, 0x12, 0xa4, 0x42,
		    0xeb, 0xc2, 0xd3, 0x6e, 0xf4, 0x71, 0x21, 0x7c,
		    0x4f, 0x3e, 0x30, 0x8e, 0x80, 0x22, 0x00, 0x0a,
		    0x65, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74,
		    0x65, 0x72, 0x00, 0x00, 0x00, 0x20, 0x00, 0x08,
		    0x00, 0x01, 0xce, 0x66, 0x5e, 0x12, 0xa4, 0x43,
		    0x80, 0x28, 0x00, 0x04, 0xb6, 0x99, 0xbb, 0x02,
		    0x01, 0x01, 0x00, 0x24, 0x21, 0x12, 0xa4, 0x42,
		],
		want_tid: vec![
		    0xeb, 0xc2, 0xd3, 0x6e, 0xf4, 0x71, 0x21, 0x7c,
		    0x4f, 0x3e, 0x30, 0x8e,
		],
		want_addr: IpAddr::V4(Ipv4Addr::from([127, 0, 0, 1])),
		want_port: 61300,
	    },
	    ResponseTestCase{
		name: "stuntman-server ipv6",
		data: vec![
		    0x01, 0x01, 0x00, 0x48, 0x21, 0x12, 0xa4, 0x42,
		    0x06, 0xf5, 0x66, 0x85, 0xd2, 0x8a, 0xf3, 0xe6,
		    0x9c, 0xe3, 0x41, 0xe2, 0x00, 0x01, 0x00, 0x14,
		    0x00, 0x02, 0x90, 0xce, 0x26, 0x02, 0x00, 0xd1,
		    0xb4, 0xcf, 0xc1, 0x00, 0x38, 0xb2, 0x31, 0xff,
		    0xfe, 0xef, 0x96, 0xf6, 0x80, 0x2b, 0x00, 0x14,
		    0x00, 0x02, 0x0d, 0x96, 0x26, 0x04, 0xa8, 0x80,
		    0x00, 0x02, 0x00, 0xd1, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0xc5, 0x70, 0x01, 0x00, 0x20, 0x00, 0x14,
		    0x00, 0x02, 0xb1, 0xdc, 0x07, 0x10, 0xa4, 0x93,
		    0xb2, 0x3a, 0xa7, 0x85, 0xea, 0x38, 0xc2, 0x19,
		    0x62, 0x0c, 0xd7, 0x14,
		],
		want_tid: vec![
		    6, 245, 102, 133, 210, 138, 243, 230, 156, 227,
		    65, 226,
		],
		want_addr: "2602:d1:b4cf:c100:38b2:31ff:feef:96f6".parse().unwrap(),
		want_port: 37070,
	    },
	    // Testing STUN attribute padding rules using STUN software attribute
	    // with values of 1 & 3 length respectively before the XorMappedAddress attribute
	    ResponseTestCase {
		name: "software-a",
		data: vec![
		    0x01, 0x01, 0x00, 0x14, 0x21, 0x12, 0xa4, 0x42,
		    0xeb, 0xc2, 0xd3, 0x6e, 0xf4, 0x71, 0x21, 0x7c,
		    0x4f, 0x3e, 0x30, 0x8e, 0x80, 0x22, 0x00, 0x01,
		    0x61, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x08,
		    0x00, 0x01, 0xce, 0x66, 0x5e, 0x12, 0xa4, 0x43,
		],
		want_tid: vec![
		    0xeb, 0xc2, 0xd3, 0x6e, 0xf4, 0x71, 0x21, 0x7c,
		    0x4f, 0x3e, 0x30, 0x8e,
		],
		want_addr: IpAddr::V4(Ipv4Addr::from([127, 0, 0, 1])),
		want_port: 61300,
	    },
            ResponseTestCase	{
		name: "software-abc",
		data: vec![
		    0x01, 0x01, 0x00, 0x14, 0x21, 0x12, 0xa4, 0x42,
		    0xeb, 0xc2, 0xd3, 0x6e, 0xf4, 0x71, 0x21, 0x7c,
		    0x4f, 0x3e, 0x30, 0x8e, 0x80, 0x22, 0x00, 0x03,
		    0x61, 0x62, 0x63, 0x00, 0x00, 0x20, 0x00, 0x08,
		    0x00, 0x01, 0xce, 0x66, 0x5e, 0x12, 0xa4, 0x43,
		],
		want_tid: vec![
		    0xeb, 0xc2, 0xd3, 0x6e, 0xf4, 0x71, 0x21, 0x7c,
		    0x4f, 0x3e, 0x30, 0x8e,
		],
		want_addr: IpAddr::V4(Ipv4Addr::from([127, 0, 0, 1])),
		want_port: 61300,
	    },
            ResponseTestCase	{
	        name:     "no-4in6",
	        data:     hex::decode("010100182112a4424fd5d202dcb37d31fc773306002000140002cd3d2112a4424fd5d202dcb382ce2dc3fcc7").unwrap(),
	        want_tid:  vec![79, 213, 210, 2, 220, 179, 125, 49, 252, 119, 51, 6],
	        want_addr: IpAddr::V4(Ipv4Addr::from([209, 180, 207, 193])),
		want_port: 60463,
	    },
        ];

        for (i, test) in cases.into_iter().enumerate() {
            println!("Case {i}");
            let (tx, addr_port) = parse_response(&test.data).unwrap();

            assert_eq!(tx.as_bytes(), &test.want_tid[..]);
            assert_eq!(addr_port.ip(), test.want_addr);
            assert_eq!(addr_port.port(), test.want_port);
        }
    }

    #[test]
    fn test_parse_binding_request() {
        todo!()
        // func TestParseBindingRequest(t *testing.T) {
        //     tx := stun.NewTxID();
        //     req := stun.Request(tx);
        //     gotTx, err := stun.ParseBindingRequest(req).unwrap();
        //     if gotTx != tx {
        //         t.Errorf("original txID %q != got txID %q", tx, gotTx)
        //     }
    }

    #[test]
    fn test_response() {
        todo!()
        // txN := func(n int) (x stun.TxID) {
        // 	for i := range x {
        // 		x[i] = byte(n)
        // 	}
        // 	return
        // }
        // tests := []struct {
        // 	tx   stun.TxID
        // 	addr netip.Addr
        // 	port uint16
        // }{
        // 	{tx: txN(1), addr: netip.MustParseAddr("1.2.3.4"), port: 254},
        // 	{tx: txN(2), addr: netip.MustParseAddr("1.2.3.4"), port: 257},
        // 	{tx: txN(3), addr: netip.MustParseAddr("1::4"), port: 254},
        // 	{tx: txN(4), addr: netip.MustParseAddr("1::4"), port: 257},
        // }
        // for _, tt := range tests {
        // 	res := stun.Response(tt.tx, netip.AddrPortFrom(tt.addr, tt.port))
        // 	tx2, addr2, err := stun.ParseResponse(res)
        // 	if err != nil {
        // 		t.Errorf("TX %x: error: %v", tt.tx, err)
        // 		continue
        // 	}
        // 	if tt.tx != tx2 {
        // 		t.Errorf("TX %x: got TxID = %v", tt.tx, tx2)
        // 	}
        // 	if tt.addr.Compare(addr2.Addr()) != 0 {
        // 		t.Errorf("TX %x: addr = %v; want %v", tt.tx, addr2.Addr(), tt.addr)
        // 	}
        // 	if tt.port != addr2.Port() {
        // 		t.Errorf("TX %x: port = %v; want %v", tt.tx, addr2.Port(), tt.port)
        // 	}
        // }
    }
}
