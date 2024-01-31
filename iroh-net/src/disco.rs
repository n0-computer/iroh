//! Contains the discovery message types.
//!
//! A discovery message is:
//!
//! Header:
//!
//! ```ignore
//! magic:            [u8; 6]  // “TS💬” (0x54 53 f0 9f 92 ac)
//! sender_disco_pub: [u8; 32] // nacl public key
//! nonce:            [u8; 24]
//! ````
//! The recipient then decrypts the bytes following (the nacl secretbox)
//! and then the inner payload structure is:
//!
//! ```ignore
//! message_type:    u8   // (the MessageType constants below)
//! message_version: u8   // (0 for now; but always ignore bytes at the end)
//! message_payload: &[u8]
//! ```

use std::{
    fmt::Display,
    net::{IpAddr, SocketAddr},
};

use anyhow::{anyhow, bail, ensure, Result};
use url::Url;

use crate::{derp::DerpUrl, key, net::ip::to_canonical};

use super::{key::PublicKey, stun};

// TODO: custom magicn
/// The 6 byte header of all discovery messages.
pub const MAGIC: &str = "TS💬"; // 6 bytes: 0x54 53 f0 9f 92 ac
pub const MAGIC_LEN: usize = MAGIC.as_bytes().len();

/// Current Version.
const V0: u8 = 0;

pub(crate) const KEY_LEN: usize = 32;
const TX_LEN: usize = 12;

// Sizes for the inner message structure.

/// Header: Type | Version
const HEADER_LEN: usize = 2;

const PING_LEN: usize = TX_LEN + key::PUBLIC_KEY_LENGTH;
const EP_LENGTH: usize = 16 + 2; // 16 byte IP address + 2 byte port

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MessageType {
    Ping = 0x01,
    Pong = 0x02,
    CallMeMaybe = 0x03,
}

impl TryFrom<u8> for MessageType {
    type Error = u8;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(MessageType::Ping),
            0x02 => Ok(MessageType::Pong),
            0x03 => Ok(MessageType::CallMeMaybe),
            _ => Err(value),
        }
    }
}

const MESSAGE_HEADER_LEN: usize = MAGIC_LEN + KEY_LEN;

pub fn encode_message(sender: &PublicKey, seal: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(MESSAGE_HEADER_LEN);
    out.extend_from_slice(MAGIC.as_bytes());
    out.extend_from_slice(sender.as_bytes());
    out.extend(seal);

    out
}

/// Reports whether p looks like it's a packet containing an encrypted disco message.
pub fn looks_like_disco_wrapper(p: &[u8]) -> bool {
    if p.len() < MESSAGE_HEADER_LEN {
        return false;
    }

    &p[..MAGIC_LEN] == MAGIC.as_bytes()
}

/// If `p` looks like a disco message it returns the slice of `p` that represents the disco public key source,
/// and the part that is the box.
pub fn source_and_box(p: &[u8]) -> Option<(PublicKey, &[u8])> {
    if !looks_like_disco_wrapper(p) {
        return None;
    }

    let source = &p[MAGIC_LEN..MAGIC_LEN + KEY_LEN];
    let sender = PublicKey::try_from(source).ok()?;
    let sealed_box = &p[MAGIC_LEN + KEY_LEN..];
    Some((sender, sealed_box))
}

/// A discovery message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Ping(Ping),
    Pong(Pong),
    CallMeMaybe(CallMeMaybe),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ping {
    /// Random client-generated per-ping transaction ID.
    pub tx_id: stun::TransactionId,

    /// Allegedly the ping sender's wireguard public key.
    /// It shouldn't be trusted by itself, but can be combined with
    /// netmap data to reduce the discokey:nodekey relation from 1:N to 1:1.
    pub node_key: PublicKey,
}

/// A response a Ping.
///
/// It includes the sender's source IP + port, so it's effectively a STUN response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pong {
    pub tx_id: stun::TransactionId,
    /// 18 bytes (16+2) on the wire; v4-mapped ipv6 for IPv4.
    pub src: SendAddr,
}

/// Addresses to which we can send. This is either a UDP or a derp address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SendAddr {
    /// UDP, the ip addr.
    Udp(SocketAddr),
    /// Derp Url.
    Derp(DerpUrl),
}

impl SendAddr {
    /// Returns if this is a `derp` addr.
    pub fn is_derp(&self) -> bool {
        matches!(self, Self::Derp(_))
    }

    /// Returns the `Some(Url)` if it is a derp addr.
    pub fn derp_url(&self) -> Option<Url> {
        match self {
            Self::Derp(url) => Some(url.0.clone()),
            Self::Udp(_) => None,
        }
    }
}

impl PartialEq<SocketAddr> for SendAddr {
    fn eq(&self, other: &SocketAddr) -> bool {
        match self {
            Self::Derp(_) => false,
            Self::Udp(addr) => addr.eq(other),
        }
    }
}

impl Display for SendAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendAddr::Derp(id) => write!(f, "Derp({})", id),
            SendAddr::Udp(addr) => write!(f, "UDP({})", addr),
        }
    }
}

/// Message sent only over DERP to request that the recipient try
/// to open up a magicsock path back to the sender.
///
/// The sender should've already sent UDP packets to the peer to open
/// up the stateful firewall mappings inbound.
///
/// The recipient may choose to not open a path back, if it's already happy with its path.
/// But usually it will.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallMeMaybe {
    /// What the peer believes its endpoints are.
    pub my_numbers: Vec<SocketAddr>,
}

impl Ping {
    fn from_bytes(ver: u8, p: &[u8]) -> Result<Self> {
        ensure!(ver == V0, "invalid version");
        // Deliberately lax on longer-than-expected messages, for future compatibility.
        ensure!(p.len() >= PING_LEN, "message too short");
        let tx_id: [u8; TX_LEN] = p[..TX_LEN].try_into().unwrap();
        let raw_key = &p[TX_LEN..TX_LEN + key::PUBLIC_KEY_LENGTH];
        let node_key = PublicKey::try_from(raw_key)?;
        let tx_id = stun::TransactionId::from(tx_id);

        Ok(Ping { tx_id, node_key })
    }

    fn as_bytes(&self) -> Vec<u8> {
        let header = msg_header(MessageType::Ping, V0);
        let mut out = vec![0u8; PING_LEN + HEADER_LEN];

        out[..HEADER_LEN].copy_from_slice(&header);
        out[HEADER_LEN..HEADER_LEN + TX_LEN].copy_from_slice(&self.tx_id);
        out[HEADER_LEN + TX_LEN..].copy_from_slice(self.node_key.as_ref());

        out
    }
}

fn send_addr_from_bytes(p: &[u8]) -> Result<SendAddr> {
    ensure!(p.len() > 2, "too short");
    match p[0] {
        0u8 => {
            ensure!(p.len() - 1 == EP_LENGTH, "invalid length");
            let addr = socket_addr_from_bytes(&p[1..]);
            Ok(SendAddr::Udp(addr))
        }
        1u8 => {
            let s = std::str::from_utf8(&p[1..])?;
            let u: Url = s.parse()?;
            Ok(SendAddr::Derp(DerpUrl(u)))
        }
        _ => {
            bail!("invalid addr type {}", p[0]);
        }
    }
}

fn send_addr_to_vec(addr: &SendAddr) -> Vec<u8> {
    match addr {
        SendAddr::Derp(url) => {
            let mut out = vec![1u8];
            out.extend_from_slice(url.to_string().as_bytes());
            out
        }
        SendAddr::Udp(ip) => {
            let mut out = vec![0u8];
            out.extend_from_slice(&socket_addr_as_bytes(ip));
            out
        }
    }
}

// Assumes p.len() == EP_LENGTH
fn socket_addr_from_bytes(p: &[u8]) -> SocketAddr {
    debug_assert_eq!(p.len(), EP_LENGTH);

    let raw_src_ip: [u8; 16] = p[..16].try_into().unwrap();
    let raw_port: [u8; 2] = p[16..].try_into().unwrap();

    let src_ip = to_canonical(IpAddr::from(raw_src_ip));
    let src_port = u16::from_le_bytes(raw_port);

    SocketAddr::new(src_ip, src_port)
}

fn socket_addr_as_bytes(addr: &SocketAddr) -> [u8; EP_LENGTH] {
    let mut out = [0u8; EP_LENGTH];
    let ipv6 = match addr.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    };
    out[..16].copy_from_slice(&ipv6.octets());
    out[16..].copy_from_slice(&addr.port().to_le_bytes());

    out
}

impl Pong {
    fn from_bytes(ver: u8, p: &[u8]) -> Result<Self> {
        ensure!(ver == V0, "invalid version");
        ensure!(p.len() >= TX_LEN, "message too short");
        let tx_id: [u8; TX_LEN] = p[..TX_LEN].try_into().unwrap();
        let tx_id = stun::TransactionId::from(tx_id);
        let src = send_addr_from_bytes(&p[TX_LEN..])?;

        Ok(Pong { tx_id, src })
    }

    fn as_bytes(&self) -> Vec<u8> {
        let header = msg_header(MessageType::Pong, V0);
        let mut out = header.to_vec();
        out.extend_from_slice(&self.tx_id);

        let src_bytes = send_addr_to_vec(&self.src);
        out.extend(src_bytes);
        out
    }
}

impl CallMeMaybe {
    fn from_bytes(ver: u8, p: &[u8]) -> Result<Self> {
        ensure!(ver == V0, "invalid version");
        ensure!(p.len() % EP_LENGTH == 0, "invalid entries");

        let num_entries = p.len() / EP_LENGTH;
        let mut m = CallMeMaybe {
            my_numbers: Vec::with_capacity(num_entries),
        };

        for chunk in p.chunks_exact(EP_LENGTH) {
            let src = socket_addr_from_bytes(chunk);
            m.my_numbers.push(src);
        }

        Ok(m)
    }

    fn as_bytes(&self) -> Vec<u8> {
        let header = msg_header(MessageType::CallMeMaybe, V0);
        let mut out = vec![0u8; HEADER_LEN + self.my_numbers.len() * EP_LENGTH];
        out[..HEADER_LEN].copy_from_slice(&header);

        for (m, chunk) in self
            .my_numbers
            .iter()
            .zip(out[HEADER_LEN..].chunks_exact_mut(EP_LENGTH))
        {
            let raw = socket_addr_as_bytes(m);
            chunk.copy_from_slice(&raw);
        }

        out
    }
}

impl Message {
    /// Parses the encrypted part of the message from inside the nacl secretbox.
    pub fn from_bytes(p: &[u8]) -> Result<Self> {
        ensure!(p.len() >= 2, "message too short");

        let t = MessageType::try_from(p[0]).map_err(|v| anyhow!("unknown message type: {}", v))?;
        let ver = p[1];
        let p = &p[2..];
        match t {
            MessageType::Ping => {
                let ping = Ping::from_bytes(ver, p)?;
                Ok(Message::Ping(ping))
            }
            MessageType::Pong => {
                let pong = Pong::from_bytes(ver, p)?;
                Ok(Message::Pong(pong))
            }
            MessageType::CallMeMaybe => {
                let cm = CallMeMaybe::from_bytes(ver, p)?;
                Ok(Message::CallMeMaybe(cm))
            }
        }
    }

    /// Serialize this message to bytes.
    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            Message::Ping(ping) => ping.as_bytes(),
            Message::Pong(pong) => pong.as_bytes(),
            Message::CallMeMaybe(cm) => cm.as_bytes(),
        }
    }
}

impl Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Message::Ping(ping) => {
                write!(f, "Ping(tx={})", hex::encode(ping.tx_id))
            }
            Message::Pong(pong) => {
                write!(f, "Pong(tx={})", hex::encode(pong.tx_id))
            }
            Message::CallMeMaybe(_) => {
                write!(f, "CallMeMaybe")
            }
        }
    }
}

const fn msg_header(t: MessageType, ver: u8) -> [u8; HEADER_LEN] {
    [t as u8, ver]
}

#[cfg(test)]
mod tests {
    use crate::key::SecretKey;

    use super::*;

    #[test]
    fn test_to_from_bytes() {
        struct Test {
            name: &'static str,
            m: Message,
            want: &'static str,
        }
        let tests = [
            Test {
                name: "ping_with_nodekey_src",
                m: Message::Ping(Ping {
                    tx_id: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12].into(),
                    node_key: PublicKey::try_from(&[
                        190, 243, 65, 104, 37, 102, 175, 75, 243, 22, 69, 200, 167, 107, 24, 63, 216, 140, 120, 43, 4, 112, 16, 62, 117, 155, 45, 215, 72, 175, 40, 189][..]).unwrap(),
                }),
                want: "01 00 01 02 03 04 05 06 07 08 09 0a 0b 0c be f3 41 68 25 66 af 4b f3 16 45 c8 a7 6b 18 3f d8 8c 78 2b 04 70 10 3e 75 9b 2d d7 48 af 28 bd",
            },
            Test {
                name: "pong",
                m: Message::Pong(Pong{
                    tx_id: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12].into(),
                    src:  SendAddr::Udp("2.3.4.5:1234".parse().unwrap()),
                }),
                want: "02 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 00 00 00 00 00 00 00 00 00 00 00 ff ff 02 03 04 05 d2 04",
            },
            Test {
                name: "pongv6",
                m: Message::Pong(Pong {
                    tx_id: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12].into(),
                    src: SendAddr::Udp("[fed0::12]:6666".parse().unwrap()),
                }),
                want: "02 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 00 fe d0 00 00 00 00 00 00 00 00 00 00 00 00 00 12 0a 1a",
            },
            Test {
                name: "call_me_maybe",
                m: Message::CallMeMaybe(CallMeMaybe { my_numbers: Vec::new() }),
                want: "03 00",
            },
            Test {
                name: "call_me_maybe_endpoints",
                m: Message::CallMeMaybe(CallMeMaybe {
                    my_numbers: vec![
                        "1.2.3.4:567".parse().unwrap(),
                        "[2001::3456]:789".parse().unwrap(),
                    ],
                }),
                want: "03 00 00 00 00 00 00 00 00 00 00 00 ff ff 01 02 03 04 37 02 20 01 00 00 00 00 00 00 00 00 00 00 00 00 34 56 15 03",
            },
        ];
        for test in tests {
            println!("{}", test.name);

            let got = test.m.as_bytes();
            assert_eq!(
                got,
                hex::decode(test.want.replace(' ', "")).unwrap(),
                "wrong as_bytes"
            );

            let back = Message::from_bytes(&got).expect("failed to parse");
            assert_eq!(test.m, back, "wrong from_bytes");
        }
    }

    #[test]
    fn test_extraction() {
        let sender_key = SecretKey::generate();
        let recv_key = SecretKey::generate();

        let msg = Message::Ping(Ping {
            tx_id: stun::TransactionId::default(),
            node_key: sender_key.public(),
        });

        let shared = sender_key.shared(&recv_key.public());
        let mut seal = msg.as_bytes();
        shared.seal(&mut seal);

        let bytes = encode_message(&sender_key.public(), seal.clone());

        assert!(looks_like_disco_wrapper(&bytes));
        assert_eq!(source_and_box(&bytes).unwrap().0, sender_key.public());

        let (raw_key, seal_back) = source_and_box(&bytes).unwrap();
        assert_eq!(raw_key, sender_key.public());
        assert_eq!(seal_back, seal);

        let shared_recv = recv_key.shared(&sender_key.public());
        let mut open_seal = seal_back.to_vec();
        shared_recv
            .open(&mut open_seal)
            .expect("failed to open seal_back");
        let msg_back = Message::from_bytes(&open_seal).unwrap();
        assert_eq!(msg_back, msg);
    }
}
