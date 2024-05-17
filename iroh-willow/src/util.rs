use std::{io, time::SystemTime};

pub mod channel;
pub mod task_set;
pub mod queue;

pub fn system_time_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("time drift")
        .as_micros() as u64
}

pub trait Encoder: std::fmt::Debug {
    fn encoded_len(&self) -> usize;

    fn encode_into<W: io::Write>(&self, out: &mut W) -> anyhow::Result<()>;

    fn encode(&self) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode_into(&mut out)?;
        Ok(out)
    }
}

pub trait Decoder: Sized {
    fn decode_from(data: &[u8]) -> anyhow::Result<DecodeOutcome<Self>>;
}

#[derive(Debug)]
pub enum DecodeOutcome<T> {
    NeedMoreData,
    Decoded { item: T, consumed: usize },
}

