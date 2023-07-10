//! Windows firewall integration.
//!

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

/// Handle to apply rules using the Windows Filtering Platform (Fwpm).
#[derive(Debug)]
pub struct Firewall {
    session: Session,
    provider_id: GUID,
    sublayer_id: GUID,
}

const WEIGHT_IROH_TRAFFIC: u16 = 15;

impl Firewall {
    pub fn new() -> Result<Self> {
        let session = Session::new("Iroh firewall", "rules for iroh-net", true)?;
        let provider_id = GUID::new()?;
        session.add_provider(Provider::new(provider_id, "Iroh provider"))?;
        let sublayer_id = GUID::new()?;
        session.add_sublayer(Sublayer::new(
            sublayer_id,
            "Iroh permissive and blocking filters",
            0,
        ))?;

        let this = Firewall {
            session,
            provider_id,
            sublayer_id,
        };

        this.enable()?;
        Ok(this)
    }

    fn enable(&self) -> Result<()> {
        self.permit_iroh_service()?;
    }

    fn permit_iroh_serivce(&self) -> Result<()> {
        // TODO:

        Ok(())
    }

    fn permit_dns(&self) -> Result<()> {
        let conditions = [
            Match {
                field: FieldId::IpRemotePort,
                op: MatchType::Equal,
                value: MatchValue::U16(53),
            },
            // Repeat the condition type for logical OR.
            Match {
                field: FieldId::IpProtocol,
                op: MatchType::Equal,
                value: MatchValue::IpProtoUdp,
            },
            Match {
                field: FieldId::IpProtocol,
                op: MatchType::Equal,
                value: MatchValue::IpProtoTcp,
            },
        ];
        self.add_rules(
            "DNS",
            WEIGHT_IROH_TRAFFIC,
            conditions,
            Action::Permit,
            protocolAll,
            directionBoth,
        )?;
        Ok(())
    }

    // fn add_rules(&self, name: &str, )
}

/// An action the filtering system can execute.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(i32)]
enum Action {
    Block = 0x1001,
    Permit = 0x1002,
    CalloutTerminating = 0x5003,
    CalloutInspection = 0x6004,
    CalloutUnknown = 0x4005,
}

enum FieldId {
    IpProtocol,
}

/// Wrapper around `FWP_MATCH_TYPE`
#[derive(Copy, Clone, PartialEq, Eq, Debug, derive_more::Display)]
#[repr(i32)]
enum MatchType {
    #[display("==")]
    Equal = 0,
    #[display(">")]
    Greater,
    #[display("<")]
    Less,
    #[display(">=")]
    GreaterOrEqual,
    #[display("<=")]
    LessOrEqual,
    #[display("in")]
    Range,
    #[display("F[all]")]
    FlagsAllSet,
    #[display("F[any]")]
    FlagsAnySet,
    #[display("F[none]")]
    FlagsNoneSet,
    #[display("i==")]
    EqualCaseInsensitive,
    #[display("!=")]
    NotEqual,
    #[display("pfx")]
    TypePrefix,
    #[display("!pfx")]
    TypeNotPrefix,
}

impl Into<FWP_MATCH_TYPE> for MatchType {
    fn into(self) -> FWP_MATCH_TYPE {
        FWP_MATCH_TYPE(self as i32)
    }
}

/// Wrapper around `FWPM_CONDTION_VALUE0_0`.
enum MatchValue {
    U16(u16),
    IpProtoUdp,
    IpProtoTcp,
}

/// Wrapper around `FWPM_FILTER_CONDITION0`
struct Match {
    field: FieldId,
    op: MatchType,
    value: (),
}

struct Rule {}

/// Wrapper around Fwpm Engine.
#[derive(Debug)]
struct Session {
    engine_handle: HANDLE,
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.engine_handle.is_invalid() {
            return;
        }
        let ret = unsafe { FwpmEngineClose0(self.engine_handle) };
        let ret = WIN32_ERRRO(ret).ok().context("FwpmEngineClose0");
        if ret.is_err() {
            tracing::warn!("{:?}", ret);
        }
    }
}

impl Session {
    /// Creates a new session.
    fn new(name: &str, description: &str, dynamic: bool) -> Result<Self> {
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
            FwpmEngineOpen0(
                None,
                RPC_C_AUTHN_WINNT,
                None,
                Some(&session),
                &mut engine_handle,
            )
        };
        WIN32_ERROR(ret).ok().context("FwpmEngineOpen0")?;

        Ok(Session { engine_handle })
    }

    /// Creates a new provider.
    fn add_provider(&self, mut provider: Provider) -> Result<()> {
        anyhow::ensure!(provider.id != GUID::zeroed(), "ID must not be zero");

        let ret = unsafe {
            let p = provider.as_fwpm_provider0();
            FwpmProviderAdd0(self.engine_handle, &p, None)
        };
        WIN32_ERROR(ret).ok().context("FwpmProviderAdd0")?;

        Ok(())
    }

    fn add_sublayer(&self, mut layer: Sublayer) -> Result<()> {
        anyhow::ensure!(layer.id != GUID::zeroed(), "ID must not be zero");

        let ret = unsafe {
            let s = provider.as_fwpm_sublayer0();
            FwpmSublyerAdd0(self.engine_handle, &s, None)
        };
        WIN32_ERROR(ret).ok().context("FwpmSublayerAdd0")?;

        Ok(())
    }
}

/// Wrapper around `FWPM_SUBLAYER0`.
#[derive(Debug)]
struct Sublayer {
    id: GUID,
    name: U16CString,
    weight: u16,
}

impl Sublayer {
    fn new(id: GUID, name: &str, weight: u16) -> Self {
        Sublayer {
            id,
            name: U16CString::from_str(name),
            weight,
        }
    }

    unsafe fn as_fwpm_sublayer(&mut self) -> FWPM_SUBLAYER0 {
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

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_basics() {
        let session = Session::new("test", "this is a test", true);
        println!("{session:?}");
    }
}
