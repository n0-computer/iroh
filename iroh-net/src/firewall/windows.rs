//! Windows firewall integration.
//!

use anyhow::{Result, Context};
use widestring::U16CString;
use windows::Win32::{
    Foundation::{HANDLE, WIN32_ERROR},
    NetworkManagement::WindowsFilteringPlatform::{
        FwpmEngineClose0, FwpmEngineOpen0, FWPM_DISPLAY_DATA0, FWPM_SESSION0,
        FWPM_SESSION_FLAG_DYNAMIC,
    },
    System::Rpc::RPC_C_AUTHN_WINNT,
};

/// Wrapper around Fwpm Engine
#[derive(Debug)]
pub struct Session {
    engine_handle: HANDLE,
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.engine_handle.is_invalid() {
           return; 
        }
        let ret = unsafe { FwpmEngineClose0(self.engine_handle) };
        println!("got {ret}");
    }
}

impl Session {
    pub fn new(name: &str, description: &str, dynamic: bool) -> Result<Self> {
        let mut engine_handle = HANDLE::default();
        let flags = if dynamic {
            FWPM_SESSION_FLAG_DYNAMIC
        } else {
            0
        };
        let mut name = U16CString::from_str(name)?;
        let mut description = U16CString::from_str(description)?;
        let session = FWPM_SESSION0 {
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR::from_raw(name.as_mut_ptr()),
                description: windows::core::PWSTR::from_raw(description.as_mut_ptr()),
            },
            flags,
            ..Default::default()
        };
        let ret = unsafe {
            FwpmEngineOpen0(None, RPC_C_AUTHN_WINNT, None, Some(&session), &mut engine_handle)
        };
        WIN32_ERROR(ret).ok().context("FwpmEngineOpen0")?;
        println!("got {ret}");

        Ok(Session { engine_handle })
    }
}



#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_basics() {
        let session = Session::new("test", "this is a test", true);
        println!("{session:?}");
    }
}
