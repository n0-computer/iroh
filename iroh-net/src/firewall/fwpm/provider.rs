use anyhow::Result;
use widestring::U16CString;
use windows::{
    core::{GUID, PWSTR},
    Win32::NetworkManagement::WindowsFilteringPlatform::{
        FWPM_DISPLAY_DATA0, FWPM_PROVIDER0, FWPM_PROVIDER_FLAG_PERSISTENT, FWP_BYTE_BLOB,
    },
};

/// Stores the state associated with a policy provider.
///
/// Wrapper around `FWPM_PROVIDER0`.
/// <https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_provider0>
#[derive(Debug)]
pub struct Provider {
    /// Unique identifier for this provider.
    pub id: GUID,
    /// A short an descriptive name.
    pub name: U16CString,
    /// A longer description of the provider.
    pub description: U16CString,
    /// Optional opaque data that can be held on behalf of the provider.
    pub provider_data: Option<Vec<u8>>,
    /// Optional Windows service name. If present,
    /// the rules owned by this Provider are only activated when the service is active.
    pub service_name: Option<U16CString>,
    /// Indicates whether the provider is preserved across restarts of the filtering engine.
    pub persistent: bool,
    /// Indicates whether the rules owned by this Provider are disabled due to its
    /// associated service being disabled. Read-only, ignored on Provider creation.
    pub disabled: bool,
}

impl Provider {
    /// Create a provider with minimal setup.
    pub fn new(id: GUID, name: &str) -> Result<Self> {
        Ok(Provider {
            id,
            name: U16CString::from_str(name)?,
            description: U16CString::default(),
            provider_data: None,
            service_name: None,
            persistent: false,
            disabled: false,
        })
    }

    pub(super) unsafe fn as_fwpm_provider0(&mut self) -> FWPM_PROVIDER0 {
        let mut flags = 0u32;
        if self.persistent {
            flags |= FWPM_PROVIDER_FLAG_PERSISTENT;
        }

        let service_name = self
            .service_name
            .as_mut()
            .map(|n| PWSTR::from_raw(n.as_mut_ptr()))
            .unwrap_or_else(|| PWSTR::null());

        FWPM_PROVIDER0 {
            providerKey: self.id,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR::from_raw(self.name.as_mut_ptr()),
                description: PWSTR::from_raw(self.name.as_mut_ptr()),
            },
            flags,
            providerData: FWP_BYTE_BLOB {
                size: self
                    .provider_data
                    .as_ref()
                    .map(|d| d.len() as u32)
                    .unwrap_or_default(),
                data: self
                    .provider_data
                    .as_mut()
                    .map(|d| d.as_mut_ptr())
                    .unwrap_or_else(|| std::ptr::null_mut()),
            },
            serviceName: service_name,
        }
    }
}
