//! Various database implementations for storing blob data
#[cfg(feature = "flat-db")]
pub mod flat;
pub mod mem;

pub mod readonly_mem;

fn flatten_to_io<T>(
    e: std::result::Result<std::io::Result<T>, tokio::task::JoinError>,
) -> std::io::Result<T> {
    match e {
        Ok(x) => x,
        Err(cause) => Err(std::io::Error::new(std::io::ErrorKind::Other, cause)),
    }
}

/// Create a 16 byte unique ID.
fn new_uuid() -> [u8; 16] {
    use rand::Rng;
    rand::thread_rng().gen::<[u8; 16]>()
}

/// Create temp file name based on a 16 byte UUID.
fn temp_name() -> String {
    format!("{}.temp", hex::encode(new_uuid()))
}

#[derive(Debug, Default, Clone)]
struct TempCounters {
    /// number of raw temp tags for a hash
    raw: u64,
    /// number of hash seq temp tags for a hash
    hash_seq: u64,
}

impl TempCounters {
    fn counter(&mut self, format: iroh_bytes::util::BlobFormat) -> &mut u64 {
        match format {
            iroh_bytes::util::BlobFormat::Raw => &mut self.raw,
            iroh_bytes::util::BlobFormat::HashSeq => &mut self.hash_seq,
        }
    }

    fn inc(&mut self, format: iroh_bytes::util::BlobFormat) {
        let counter = self.counter(format);
        *counter = counter.checked_add(1).unwrap();
    }

    fn dec(&mut self, format: iroh_bytes::util::BlobFormat) {
        let counter = self.counter(format);
        *counter = counter.saturating_sub(1);
    }

    fn is_empty(&self) -> bool {
        self.raw == 0 && self.hash_seq == 0
    }
}

#[derive(Debug, Clone, Default)]
struct TempCounterMap(std::collections::BTreeMap<iroh_bytes::Hash, TempCounters>);

impl TempCounterMap {
    fn inc(&mut self, value: &iroh_bytes::util::HashAndFormat) {
        let iroh_bytes::util::HashAndFormat { hash, format } = value;
        self.0.entry(*hash).or_default().inc(*format)
    }

    fn dec(&mut self, value: &iroh_bytes::util::HashAndFormat) {
        let iroh_bytes::util::HashAndFormat { hash, format } = value;
        let counters = self.0.get_mut(hash).unwrap();
        counters.dec(*format);
        if counters.is_empty() {
            self.0.remove(hash);
        }
    }

    fn contains(&self, hash: &iroh_bytes::Hash) -> bool {
        self.0.contains_key(hash)
    }

    fn keys(&self) -> impl Iterator<Item = iroh_bytes::util::HashAndFormat> {
        let mut res = Vec::new();
        for (k, v) in self.0.iter() {
            if v.raw > 0 {
                res.push(iroh_bytes::util::HashAndFormat::raw(*k));
            }
            if v.hash_seq > 0 {
                res.push(iroh_bytes::util::HashAndFormat::hash_seq(*k));
            }
        }
        res.into_iter()
    }
}
