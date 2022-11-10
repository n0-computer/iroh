use anyhow::Result;
use cid::Cid;
use libp2p::{Multiaddr, PeerId};
use multihash::Multihash;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use tracing::trace;

/// API connection to the indexer nodes, as implemented in
/// https://github.com/filecoin-project/storetheindex.
#[derive(Debug, Clone)]
pub struct Indexer {
    endpoint: Url,
    client: Client,
}

/// Public endpoint of the indexer nodes.
pub const CID_CONTACT: &str = "https://cid.contact/cid/";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Provider {
    #[serde(rename = "ID")]
    pub id: PeerId,
    pub addrs: Vec<Multiaddr>,
}

impl Indexer {
    pub fn new(endpoint: Url) -> Result<Self> {
        let client = Client::new();

        Ok(Self { client, endpoint })
    }

    /// Returns all available bitswap providers.
    pub async fn find_providers(&self, cid: Cid) -> Result<Vec<Provider>> {
        let url = self.endpoint.join(&cid.to_string())?;
        trace!("requesting providers from {}", url);
        let result = self
            .client
            .get(url)
            .send()
            .await?
            .json::<FindResult>()
            .await?;
        let providers = result
            .multihash_results
            .into_iter()
            .flat_map(|r| r.provider_results)
            .filter_map(|r| {
                if r.metadata == Transport::Bitswap {
                    Some(r.provider)
                } else {
                    None
                }
            })
            .collect();
        Ok(providers)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
struct FindResult {
    pub multihash_results: Vec<MultihashResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
struct MultihashResult {
    #[serde(with = "base64_multihash")]
    pub multihash: Multihash,
    pub provider_results: Vec<ProviderResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
struct ProviderResult {
    #[serde(rename = "ContextID")]
    pub context_id: String,
    #[serde(with = "base64_provider")]
    pub metadata: Transport,
    pub provider: Provider,
}

mod base64_multihash {
    use multihash::Multihash;
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(mh: &Multihash, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&base64::encode(mh.to_bytes()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Multihash, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <&str>::deserialize(deserializer)?;
        let bytes = base64::decode(s).map_err(de::Error::custom)?;
        let multihash = Multihash::from_bytes(&bytes).map_err(de::Error::custom)?;
        Ok(multihash)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Transport {
    Bitswap = 0x900,
    FilecoinGraphsyncV1 = 0x910,
    Unknown,
}

impl From<u32> for Transport {
    fn from(raw: u32) -> Self {
        if raw == 0x900 {
            Transport::Bitswap
        } else if raw == 0x910 {
            Transport::FilecoinGraphsyncV1
        } else {
            Transport::Unknown
        }
    }
}

mod base64_provider {
    use serde::{de, Deserialize, Deserializer, Serializer};

    use super::Transport;

    pub fn serialize<S>(t: &Transport, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = unsigned_varint::encode::u32_buffer();
        unsigned_varint::encode::u32(*t as u32, &mut bytes);
        serializer.serialize_str(&base64::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Transport, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <&str>::deserialize(deserializer)?;
        let bytes = base64::decode(s).map_err(de::Error::custom)?;
        let (raw, _) = unsigned_varint::decode::u32(&bytes).map_err(de::Error::custom)?;
        let transport = Transport::from(raw);
        Ok(transport)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ser_de() {
        let input = r#"{
"MultihashResults":[{
  "Multihash":"EiDVNlzli2ONH3OslRv1Q0BRCKUCsERWs3RbthTVu6Xptg==",
  "ProviderResults":[{
    "ContextID":"YmFndXFlZXJha3ppdzRwaWxuZmV5ZGFtNTdlZ2RxZTRxZjR4bzVuZmxqZG56emwzanV0YXJtbWltdHNqcQ==",
    "Metadata":"gBI=",
    "Provider": {
      "ID":"QmQzqxhK82kAmKvARFZSkUVS6fo9sySaiogAnx5EnZ6ZmC",
      "Addrs":["/dns4/elastic.dag.house/tcp/443/wss"]
    }
  }]
}]}
"#;
        let res: FindResult = serde_json::from_str(input).unwrap();
        assert_eq!(res.multihash_results.len(), 1);
        let res = &res.multihash_results[0];
        assert_eq!(res.provider_results.len(), 1);
        assert_eq!(
            res.provider_results[0].provider.id,
            "QmQzqxhK82kAmKvARFZSkUVS6fo9sySaiogAnx5EnZ6ZmC"
                .parse()
                .unwrap(),
        );
        assert_eq!(res.provider_results[0].provider.addrs.len(), 1);
        assert_eq!(res.provider_results[0].metadata, Transport::Bitswap);
    }

    #[tokio::test]
    async fn test_find_providers() -> Result<()> {
        let test_cid: Cid =
            "bafybeigvgzoolc3drupxhlevdp2ugqcrbcsqfmcek2zxiw5wctk3xjpjwy".parse()?;
        let indexer = Indexer::new(CID_CONTACT.parse()?)?;
        let providers = indexer.find_providers(test_cid).await?;
        dbg!(&providers);
        assert!(!providers.is_empty());

        Ok(())
    }
}
