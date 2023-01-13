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

        let out = dir.join("out");
        let opts = client::Options {
            out: Some(out.clone()),
            ..Default::default()
        };
        client::run(hash, opts).await?;
        let got = tokio::fs::read(out).await?;
        let expect = tokio::fs::read(path).await?;
        assert_eq!(expect, got);

        Ok(())
    }
}
