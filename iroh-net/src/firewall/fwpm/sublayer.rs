use anyhow::{Context, Result};
use widestring::U16CString;
use windows::Win32::{
    Foundation::{GUID, HANDLE, WIN32_ERROR},
    NetworkManagement::WindowsFilteringPlatform::{
        FwpmEngineClose0, FwpmEngineOpen0, FwpmProviderAdd0, FwpmSublyerAdd0, FWPM_DISPLAY_DATA0,
        FWPM_PROVIDER0, FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0, FWP_MATCH_TYPE,
    },
    System::Rpc::RPC_C_AUTHN_WINNT,
};

/// Stores the state associated with a sublayer.
///
/// Wrapper around `FWPM_SUBLAYER0`.
/// <https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_sublayer0>
#[derive(Debug)]
pub struct Sublayer {
    id: GUID,
    name: U16CString,
    weight: u16,
}

impl Sublayer {
    pub fn new(id: GUID, name: &str, weight: u16) -> Self {
        Sublayer {
            id,
            name: U16CString::from_str(name),
            weight,
        }
    }

    pub(super) unsafe fn as_fwpm_sublayer(&mut self) -> FWPM_SUBLAYER0 {
        FWPM_SUBLAYER0 {
            subLayerKey: self.id,
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR::from_raw(self.name.as_mut_ptr()),
                ..Default::default()
            },
            ..Default::default()
        }
    }
}
