use std::io;

pub trait Encoder {
    fn encoded_len(&self) -> usize;

    fn encode_into<W: io::Write>(&self, out: &mut W) -> io::Result<()>;

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode_into(&mut out).expect("encoding not to fail");
        out
    }
}
