use anyhow::Result;
use widestring::U16CString;
use windows::{
    core::GUID,
    Win32::NetworkManagement::WindowsFilteringPlatform::{FWPM_DISPLAY_DATA0, FWPM_SUBLAYER0},
};

/// Stores the state associated with a sublayer.
///
/// Wrapper around `FWPM_SUBLAYER0`.
/// <https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_sublayer0>
#[derive(Debug)]
pub struct Sublayer {
    pub id: GUID,
    pub name: U16CString,
    pub weight: u16,
}

impl Sublayer {
    pub fn new(id: GUID, name: &str, weight: u16) -> Result<Self> {
        Ok(Sublayer {
            id,
            name: U16CString::from_str(name)?,
            weight,
        })
    }

    pub(super) unsafe fn as_fwpm_sublayer0(&mut self) -> FWPM_SUBLAYER0 {
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
