use anyhow::{Context, Result};
use widestring::U16CString;
use windows::{
    core::GUID,
    Win32::{
        Foundation::{HANDLE, WIN32_ERROR},
        NetworkManagement::WindowsFilteringPlatform::{
            FwpmEngineClose0, FwpmEngineOpen0, FwpmProviderAdd0, FwpmSubLayerAdd0,
            FWPM_DISPLAY_DATA0, FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC,
        },
        System::Rpc::RPC_C_AUTHN_WINNT,
    },
};

use super::{Provider, Sublayer};

/// Wrapper around Fwpm Engine.
#[derive(Debug)]
pub struct Engine {
    /// A handle to the underlying engine.
    handle: HANDLE,
}

impl Drop for Engine {
    fn drop(&mut self) {
        if self.handle.is_invalid() {
            return;
        }
        let ret = unsafe { FwpmEngineClose0(self.handle) };
        let ret = WIN32_ERROR(ret).ok().context("FwpmEngineClose0");
        if ret.is_err() {
            tracing::warn!("{:?}", ret);
        }
    }
}

impl Engine {
    /// Creates a new `Engine`.
    pub fn new(name: &str, description: &str, dynamic: bool) -> Result<Self> {
        let mut handle = HANDLE::default();
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
        let ret =
            unsafe { FwpmEngineOpen0(None, RPC_C_AUTHN_WINNT, None, Some(&session), &mut handle) };
        WIN32_ERROR(ret).ok().context("FwpmEngineOpen0")?;

        Ok(Engine { handle })
    }

    /// Creates a new provider.
    pub fn add_provider(&self, mut provider: Provider) -> Result<()> {
        anyhow::ensure!(provider.id != GUID::zeroed(), "ID must not be zero");

        let ret = unsafe {
            let p = provider.as_fwpm_provider0();
            FwpmProviderAdd0(self.handle, &p, None)
        };
        WIN32_ERROR(ret).ok().context("FwpmProviderAdd0")?;

        Ok(())
    }

    /// Creates a new sublayer.
    pub fn add_sublayer(&self, mut layer: Sublayer) -> Result<()> {
        anyhow::ensure!(layer.id != GUID::zeroed(), "ID must not be zero");

        let ret = unsafe {
            let s = layer.as_fwpm_sublayer0();
            FwpmSubLayerAdd0(self.handle, &s, None)
        };
        WIN32_ERROR(ret).ok().context("FwpmSublayerAdd0")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basics() {
        let engine = Engine::new("test", "this is a test", true);
        println!("{engine:?}");
    }
}
