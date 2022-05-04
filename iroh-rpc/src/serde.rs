/// An abstraction around serialization
/// temporarily using serde and serde_json
/// should be replaced asap
///
pub use serde::de::DeserializeOwned;
pub use serde::{Deserialize, Serialize};
use serde_json;

use crate::error::RpcError;

pub fn serialize_request<T: Serialize>(params: T) -> Result<Vec<u8>, RpcError> {
    match serde_json::to_vec(&params) {
        Ok(b) => Ok(b),
        Err(_) => Err(RpcError::BadRequest),
    }
}

pub fn deserialize_request<T: DeserializeOwned>(data: &Vec<u8>) -> Result<T, RpcError> {
    match serde_json::from_slice(data) {
        Ok(r) => Ok(r),
        Err(_) => Err(RpcError::BadRequest),
    }
}

pub fn serialize_response<T: Serialize>(params: T) -> Result<Vec<u8>, RpcError> {
    match serde_json::to_vec(&params) {
        Ok(b) => Ok(b),
        Err(_) => Err(RpcError::BadResponse),
    }
}

pub fn deserialize_response<T: DeserializeOwned>(data: &Vec<u8>) -> Result<T, RpcError> {
    match serde_json::from_slice(data) {
        Ok(r) => Ok(r),
        Err(_) => Err(RpcError::BadResponse),
    }
}

mod test {
    use super::*;

    #[derive(Serialize, Deserialize, Debug, Clone)]
    struct Cat {
        name: String,
        color: String,
        num_legs: u8,
    }

    #[test]
    fn can_serde() {
        let c = Cat {
            name: String::from("Fizz"),
            color: String::from("Grey"),
            num_legs: 4,
        };
        let v = serialize_request(c.clone()).unwrap();
        let got: Cat = deserialize_request(&v).unwrap();
        assert_eq!(c.name, got.name);
        assert_eq!(c.color, got.color);
        assert_eq!(c.num_legs, got.num_legs);

        let v = serialize_response(c.clone()).unwrap();
        let got = deserialize_response::<Cat>(&v).unwrap();
        assert_eq!(c.name, got.name);
        assert_eq!(c.color, got.color);
        assert_eq!(c.num_legs, got.num_legs);
    }

    #[test]
    fn expected_errors() {
        let v = Vec::new();
        let got_err = deserialize_request::<Cat>(&v).unwrap_err();
        let expected_error = RpcError::BadRequest;
        assert_eq!(expected_error, got_err);
        let v = Vec::new();
        let got_err = deserialize_response::<Cat>(&v).unwrap_err();
        let expected_error = RpcError::BadResponse;
        assert_eq!(expected_error, got_err);
    }
}
