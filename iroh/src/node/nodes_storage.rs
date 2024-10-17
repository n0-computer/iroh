use std::path::Path;

use anyhow::{ensure, Context, Result};
use iroh_net::NodeAddr;
use tokio::io::AsyncWriteExt;

pub(super) async fn load_node_addrs<P: AsRef<Path>>(path: P) -> Result<Vec<NodeAddr>> {
    let path = path.as_ref();
    let mut out = Vec::new();

    if tokio::fs::try_exists(&path).await.unwrap_or(false) {
        ensure!(path.is_file(), "{} is not a file", path.display());
        let contents = tokio::fs::read(path).await?;
        let mut slice: &[u8] = &contents;
        while !slice.is_empty() {
            let (node_addr, next_contents) =
                postcard::take_from_bytes(slice).context("failed to load node data")?;
            out.push(node_addr);
            slice = next_contents;
        }
    }
    Ok(out)
}

pub(super) async fn store_node_addrs<P: AsRef<Path>>(
    path: P,
    known_nodes: &[NodeAddr],
) -> Result<usize> {
    let path = path.as_ref();

    if tokio::fs::try_exists(&path).await.unwrap_or(false) {
        ensure!(path.is_file(), "{} must be a file", path.display());
    }

    // persist only the nodes which were
    // * not used at all (so we don't forget everything we loaded)
    // * were attempted to be used, and have at least one usable path
    if known_nodes.is_empty() {
        // prevent file handling if unnecessary
        return Ok(0);
    }

    let mut ext = path.extension().map(|s| s.to_owned()).unwrap_or_default();
    ext.push(".tmp");
    let tmp_path = path.with_extension(ext);

    if tokio::fs::try_exists(&tmp_path).await.unwrap_or(false) {
        tokio::fs::remove_file(&tmp_path)
            .await
            .context("failed deleting existing tmp file")?;
    }
    if let Some(parent) = tmp_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let mut tmp = tokio::fs::File::create(&tmp_path)
        .await
        .context("failed creating tmp file")?;

    let mut count = 0;
    for node_addr in known_nodes {
        let ser = postcard::to_stdvec(&node_addr).context("failed to serialize node data")?;
        tmp.write_all(&ser)
            .await
            .context("failed to persist node data")?;
        count += 1;
    }
    tmp.flush().await.context("failed to flush node data")?;
    drop(tmp);

    // move the file
    tokio::fs::rename(tmp_path, path)
        .await
        .context("failed renaming node data file")?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use iroh_net::{key::SecretKey, relay::RelayUrl};

    use super::*;

    /// Test persisting and loading of known nodes.
    #[tokio::test]
    async fn load_save_node_data() {
        let _guard = iroh_test::logging::setup();

        let mut node_map = Vec::new();

        let node_a = SecretKey::generate().public();
        let node_b = SecretKey::generate().public();
        let node_c = SecretKey::generate().public();
        let node_d = SecretKey::generate().public();

        let relay_x: RelayUrl = "https://my-relay-1.com".parse().unwrap();
        let relay_y: RelayUrl = "https://my-relay-2.com".parse().unwrap();

        let direct_addresses_a = [addr(4000), addr(4001)];
        let direct_addresses_c = [addr(5000)];

        let node_addr_a = NodeAddr::new(node_a)
            .with_relay_url(relay_x)
            .with_direct_addresses(direct_addresses_a);
        let node_addr_b = NodeAddr::new(node_b).with_relay_url(relay_y);
        let node_addr_c = NodeAddr::new(node_c).with_direct_addresses(direct_addresses_c);
        let node_addr_d = NodeAddr::new(node_d);

        node_map.push(node_addr_a);
        node_map.push(node_addr_b);
        node_map.push(node_addr_c);
        node_map.push(node_addr_d);

        let root = testdir::testdir!();
        let path = root.join("nodes.postcard");
        store_node_addrs(&path, &node_map).await.unwrap();
        let loaded = load_node_addrs(&path).await.unwrap();
        assert_eq!(node_map, loaded);
    }

    fn addr(port: u16) -> SocketAddr {
        (std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), port).into()
    }
}
