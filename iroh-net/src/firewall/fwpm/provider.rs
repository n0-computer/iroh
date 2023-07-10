/// Wrapper around `FWPM_PROVIDER0`.
#[derive(Debug)]
struct Provider {
    /// Unique identifier for this provider.
    id: GUID,
    /// A short an descriptive name.
    name: U16CString,
}

impl Provider {
    fn new(id: GUID, name: &str) -> Self {
        Provider {
            id,
            name: U16CString::from_str(name),
        }
    }

    unsafe fn as_fwpm_provider0(&mut self) -> FWPM_PROVIDER0 {
        FWPM_PROVIDER0 {
            providerKey: self.id,
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR::from_raw(self.name.as_mut_ptr()),
                ..Default::default()
            },
            ..Default::default()
        }
    }
}
