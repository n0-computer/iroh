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

/// Wrapper around `FWPM_SUBLAYER0`.
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
