use crate::ticket::Ticket;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn setup() {
    console_error_panic_hook::set_once();
    tracing_wasm::set_as_global_default();
}

#[cfg(all(feature = "base32", feature = "key"))]
#[wasm_bindgen]
pub fn parse_node_ticket(ticket: String) -> Result<JsValue, JsValue> {
    let ticket = crate::ticket::NodeTicket::deserialize(&ticket)?;
    Ok(serde_wasm_bindgen::to_value(&ticket)?)
}

#[cfg(all(feature = "base32", feature = "key"))]
#[wasm_bindgen]
pub fn parse_blob_ticket(ticket: String) -> Result<JsValue, JsValue> {
    let ticket = crate::ticket::BlobTicket::deserialize(&ticket)?;
    Ok(serde_wasm_bindgen::to_value(&ticket)?)
}

impl From<crate::ticket::Error> for JsValue {
    fn from(value: crate::ticket::Error) -> JsValue {
        let message = value.to_string();
        JsValue::from_str(&message)
    }
}
