/// Stores the state associated with a policy provider.
///
/// Wrapper around `FWPM_PROVIDER0`.
/// <https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_provider0>
#[derive(Debug)]
struct Provider {
    /// Unique identifier for this provider.
    id: GUID,
    /// A short an descriptive name.
    name: U16CString,
    /// A longer description of the provider.
    description: U16CString,
    /// Optional opaque data that can be held on behalf of the provider.
    provider_data: Option<Vec<u8>>,
    /// Optional Windows service name. If present,
    /// the rules owned by this Provider are only activated when the service is active.
    service_name: Option<U16CString>,
    /// Indicates whether the provider is preserved across restarts of the filtering engine.
    persistent: bool,
    /// Indicates whether the rules owned by this Provider are disabled due to its
    /// associated service being disabled. Read-only, ignored on Provider creation.
    disabled: bool,
}

impl Provider {
    fn new(id: GUID, name: &str) -> Self {
        Provider {
            id,
            name: U16CString::from_str(name),
            description: U16CString::default(),
            provider_data: None,
            service_name: None,
            persistent: false,
            disabled: false,
        }
    }

    unsafe fn as_fwpm_provider0(&mut self) -> FWPM_PROVIDER0 {
        let mut flags = 0u32;
        if self.persistent {
            flags |= FWPM_PROVIDER_FLAGS_PERSISTENT;
        }

        let serviceName = self
            .service_name
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
                size: self.provider_data.map(|d| d.len()).unwrap_or_default(),
                data: self
                    .provider_data
                    .map(|d| d.as_mut_ptr())
                    .unwrap_or_else(|| std::ptr::null_mut()),
            },
            serviceName,
        }
    }
}
