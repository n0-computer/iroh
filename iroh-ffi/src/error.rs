use crate::error::IrohError;
use safer_ffi::prelude::*;

impl From<anyhow::Error> for repr_c::Box<IrohError> {
    fn from(error: anyhow::Error) -> Self {
        Box::new(IrohError { inner: error }).into()
    }
}

const IROH_ERROR_OTHER: u32 = 1;

#[ffi_export]
#[derive_ReprC(rename = "iroh_error_code")]
#[repr(u32)]
/// Constant values for error codes from iroh_error_t.
pub enum IrohErrorCode {
    Other = IROH_ERROR_OTHER,
}

impl From<u32> for IrohErrorCode {
    fn from(code: u32) -> Self {
        match code {
            IROH_ERROR_OTHER => IrohErrorCode::Other,
            _ => IrohErrorCode::Other,
        }
    }
}

impl From<&IrohError> for IrohErrorCode {
    fn from(error: &IrohError) -> Self {
        match error {
            IrohError::Other(_) => IrohErrorCode::Other,
        }
    }
}

#[derive_ReprC(rename = "iroh_error")]
#[repr(opaque)]
/// @class iroh_error_t
/// An opaque struct representing an error.
pub struct IrohError {
    inner: anyhow::Error,
}

#[ffi_export]
/// @memberof ns_error_t
/// Deallocate an ns_error_t.
pub fn iroh_error_free(error: repr_c::Box<IrohError>) {
    drop(error)
}

#[ffi_export]
/// @memberof iroh_error_t
/// Returns an owned string describing the error in greater detail.
///
/// Caller is responsible for deallocating returned string via iroh_string_free.
pub fn iroh_error_message_get(error: &IrohError) -> char_p::Box {
    error
        .inner
        .to_string()
        .try_into()
        .unwrap_or_else(|_| char_p::new("Unknown"))
}

#[ffi_export]
/// @memberof ns_error_t
/// Returns an error code that identifies the error.
pub fn ns_error_code_get(error: &IrohError) -> u32 {
    IrohErrorCode::from(&error.inner) as u32
}
