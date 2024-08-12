use std::convert::Infallible;

use ufotofu::sync::{consumer::IntoVec, producer::FromSlice};
use willow_encoding::{
    sync::{Decodable, Encodable, RelativeDecodable, RelativeEncodable},
    DecodeError,
};

pub fn from_bytes<T: Decodable>(data: &[u8]) -> Result<T, DecodeError<Infallible>> {
    let mut producer = FromSlice::new(data);
    let decoded = T::decode(&mut producer)?;
    Ok(decoded)
}

pub fn to_vec<T: Encodable>(item: &T) -> Vec<u8> {
    let mut consumer = IntoVec::new();
    item.encode(&mut consumer).expect("infallible");
    consumer.into_vec()
}

pub fn from_bytes_relative<T: RelativeDecodable<U>, U>(
    previous: &U,
    data: &[u8],
) -> Result<T, DecodeError<Infallible>> {
    let mut producer = FromSlice::new(data);
    let decoded = T::relative_decode(previous, &mut producer)?;
    Ok(decoded)
}

pub fn to_vec_relative<T: RelativeEncodable<U>, U>(previous: &U, item: &T) -> Vec<u8> {
    let mut consumer = IntoVec::new();
    item.relative_encode(previous, &mut consumer)
        .expect("infallible");
    consumer.into_vec()
}
