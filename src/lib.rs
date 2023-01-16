pub mod client;
pub mod protocol;
pub mod server;

mod tls;

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use anyhow::Result;
    use testdir::testdir;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn basics() -> Result<()> {
        let dir: PathBuf = testdir!();
        let path = dir.join("hello_world");
        tokio::fs::write(&path, "hello world!").await?;
        let db = server::create_db(vec![&path]).await?;
        let hash = *db.iter().next().unwrap().0;
        tokio::task::spawn(async move {
            server::run(db, Default::default()).await.unwrap();
        });

        let opts = client::Options::default();
        let (mut source, sink) = tokio::io::duplex(1024);
        client::run(hash, opts, sink).await?;
        let expect = tokio::fs::read(path).await?;
        let mut got = Vec::new();
        source.read_to_end(&mut got).await?;

        assert_eq!(expect, got);

        Ok(())
    }
}
