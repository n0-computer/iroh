use anyhow::{Context, Result};
use futures::Stream;
use iroh_resolver::{
    resolver::{Out, OutPrettyReader, Resolver, UnixfsType},
    Path,
};
use iroh_unixfs::{content_loader::ContentLoader, Link};

#[derive(Debug)]
pub struct Data<C: ContentLoader> {
    resolver: Resolver<C>,
    root: Out,
}

impl<C> Data<C>
where
    C: ContentLoader,
{
    pub fn typ(&self) -> UnixfsType {
        self.root.metadata().unixfs_type.unwrap()
    }

    pub fn is_file(&self) -> bool {
        self.typ() == UnixfsType::File
    }

    pub fn is_dir(&self) -> bool {
        self.typ() == UnixfsType::Dir
    }

    pub fn read_dir(&self) -> Result<Option<impl Stream<Item = Result<Link>> + '_>> {
        self.root
            .unixfs_read_dir(&self.resolver, Default::default())
    }

    pub fn pretty(self) -> Result<OutPrettyReader<C>> {
        self.root.pretty(self.resolver, Default::default(), None)
    }

    pub async fn read_file(&self, link: &Link) -> Result<Data<C>> {
        let root = self
            .resolver
            .resolve(Path::from_cid(link.cid))
            .await
            .context("resolve")?;

        Ok(Data {
            resolver: self.resolver.clone(),
            root,
        })
    }
}
