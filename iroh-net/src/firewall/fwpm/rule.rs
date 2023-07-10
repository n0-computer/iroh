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

/// Wrapper around `FWPM_FILTER0`
pub struct Rule {
    /// The unique identifier for this rule.
    id: GUID,
    /// The kernel ID for this rule.
    kernel_id: u64,
    /// A short descriptive name.
    name: U16CString,
    /// Longer description of the rule.
    description: U16CString,
    /// The ID of the layer in which the rule runs.
    layer: GUID,
    /// The ID of the sublayer in which the rule runs.
    sublayer: GUID,
    /// The priority of the rule relative to other rules in its sublayer.
    weight: u64,
    /// Conditions are the tests which must pass for this rule to apply to a packet.
    conditions: Vec<FilterCondition>,
    /// The action to take on matching packets.
    action: Action,
    /// The ID of the callout to invoke. Only valid if `action` is `Action::CalloutTerminating`,
    /// or `Action::CalloutInspection``, or `Action::CalloutUnknown`.
    callout: Option<GUID>,
    /// If set, indicates that a callout action to a callout ID that isn't registered should
    /// be translated into an `Action::Permit`, rather than an `Action::Block`. Only relevant if
    /// `action` is `Action::CalloutTerminating` or `Action::CalloutUnknown`.
    permit_if_missing: bool,
    /// If set, indicates that the action type is hard and cannot be overridden except by a Veto.
    hard_action: bool,
    /// ndicates whether the rule is preserved across restarts of the filtering engine.
    persistent: bool,
    /// Indicates that this rule applies only during early
    /// boot, before the filtering engine fully starts and hands off to the normal runtime rules.
    boot_time: bool,
    /// Optionally identifies the Provider that manages this rule.
    provider: Option<GUID>,
    /// Optional opaque data that can be held on behalf of the Provider.
    provider_data: Option<Vec<u8>>,
    /// Indicates whether the rule is currently disabled due
    /// to its provider being associated with an inactive Windows service.
    disabled: bool,
}

/// An action the filtering system can execute.
///
/// Wraps `FWPM_ACTION0`.
/// <https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_action0>
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Action {
    /// Block the traffic.
    Block = 0x00000001 | FWP_ACTION_FLAG_TERMINATING,
    /// Permit the traffic.
    Permit = 0x00000002 | FWP_ACTION_FLAG_TERMINATING,
    /// Invoke a callout that always returns block or permit.
    CalloutTerminating = 0x00000003 | FWP_ACTION_FLAG_CALLOUT | FWP_ACTION_FLAG_TERMINATING,
    /// Invoke a callout that never returns block or permit.
    CalloutInspection = 0x00000004
        | FWP_ACTION_FLAG_CALLOUT
        | FWP_ACTION_FLAG_NON_TERMINATING
        | FWP_ACTION_CALLOUT_UNKNOWN,
    /// Invoke a callout that may return block or permit.
    CalloutUnknown = 0x00000005 | FWP_ACTION_FLAG_CALLOUT,
}

/// Expresses a filter condition that must be true for the action to be taken.
///
/// Wrapper around `FWPM_FILTER_CONDITION0`
///
/// <https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter_condition0>
pub struct FilterCondition {
    /// GUID of the field to be tested.
    ///
    /// See <https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-> for available values.
    field_key: GUID,
    /// Specifies the type of match to be performed.
    match_type: MatchType,
    /// Contains the value to match the field against.
    condition_value: ConditionValue,
}

/// Wrapper around `FWP_MATCH_TYPE`
///
/// <https://learn.microsoft.com/en-us/windows/win32/api/fwptypes/ne-fwptypes-fwp_match_type>
#[derive(Copy, Clone, PartialEq, Eq, Debug, derive_more::Display)]
#[repr(u32)]
pub enum MatchType {
    /// Tests whether the value is equal to the condition value.
    ///
    /// All data types support `FWP_MATCH_EQUAL`.
    #[display("==")]
    Equal = 0,
    /// Tests whether the value is greater than the condition value.
    ///
    /// Only sortable data types support FWP_MATCH_GREATER. Sortable data types
    /// consist of all integer types, FWP_BYTE_ARRAY16_TYPE, FWP_BYTE_BLOB_TYPE,
    /// and FWP_UNICODE_STRING_TYPE.
    #[display(">")]
    Greater,
    /// Tests whether the value is less than the condition value.
    ///
    /// Only sortable data types support FWP_MATCH_LESS.
    #[display("<")]
    Less,
    /// Tests whether the value is greater than or equal to the condition value.
    ///
    /// Only sortable data types support FWP_MATCH_GREATER_OR_EQUAL.
    #[display(">=")]
    GreaterOrEqual,
    /// Tests whether the value is less than or equal to the condition value.
    ///
    /// Only sortable data types support FWP_MATCH_LESS_OR_EQUAL.
    #[display("<=")]
    LessOrEqual,
    /// Tests whether the value is within a given range of condition values.
    ///
    /// Only sortable data types support FWP_MATCH_RANGE.
    #[display("in")]
    Range,
    /// Tests whether all flags are set.
    ///
    /// Only unsigned integer data types support FWP_MATCH_FLAGS_ALL_SET.
    #[display("F[all]")]
    FlagsAllSet,
    /// Tests whether any flags are set.
    ///
    /// Only unsigned integer data types support FWP_MATCH_FLAGS_ANY_SET.
    #[display("F[any]")]
    FlagsAnySet,
    /// Tests whether no flags are set.
    ///
    /// Only unsigned integer data types support FWP_MATCH_FLAGS_NONE_SET.
    #[display("F[none]")]
    FlagsNoneSet,
    /// Tests whether the value is equal to the condition value. The test is case insensitive.
    ///
    /// Only the FWP_UNICODE_STRING_TYPE data type supports FWP_MATCH_EQUAL_CASE_INSENSITIVE.
    #[display("i==")]
    EqualCaseInsensitive,
    /// Tests whether the value is not equal to the condition value.
    ///
    /// Only sortable data types support FWP_MATCH_NOT_EQUAL.
    /// Note: Available only in Windows 7 and Windows Server 2008 R2.
    #[display("!=")]
    NotEqual,
    /// This flag has a misleading name. It tests whether the value ends with the condition value, i.e.
    /// it the suffix, not the prefix.
    ///
    /// The types FWP_BYTE_BLOB_TYPE (when it contains a string) and FWP_UNICODE_STRING_TYPE support this match type.
    #[display("pfx")]
    TypePrefix,
    /// This flag has a misleading name. It tests whether the value does not end with the
    /// condition value, i.e. it checks the suffix, not the prefix.
    ///
    /// The types FWP_BYTE_BLOB_TYPE (when it contains a string) and FWP_UNICODE_STRING_TYPE support this match type.
    #[display("!pfx")]
    TypeNotPrefix,
}

impl Into<FWP_MATCH_TYPE> for MatchType {
    fn into(self) -> FWP_MATCH_TYPE {
        FWP_MATCH_TYPE(self as i32)
    }
}

/// Wrapper around `FWPM_CONDTION_VALUE0_0`.
pub enum ConditionValue {
    Uint8(u8),
    Uint16(u16),
    Uint32(u32),
    Uint64(*mut u64),
    Int8(i8),
    Int16(i16),
    Int32(i32),
    Int64(*mut i64),
    Float(f32),
    Double(*mut f64),
    ByteArray16(*mut FWP_BYTE_ARRAY16),
    Sid(*mut SID),
    Sd(*mut FWP_BYTE_BLOB),
    ByteBlob(*mut FWP_BYTE_BLOB),
    TokenInformation(*mut FWP_TOKEN_INFORMATION),
    TokenAccessInformation(*mut FWP_BYTE_BLOB),
    V4AddrAndMask(*mut FWP_V4_ADDR_AND_MASK),
    V6AddrAndMask(*mut FWP_V6_ADDR_AND_MASK),
    RangeValue(*mut FWP_RANGE0),
}

impl ConditionValue {
    pub(super) fn as_fwp_condtion_value0(&mut self) -> FWP_CONDITION_VALUE0 {
        use ConditionValue::*;

        let typ = self.fwp_data_type();
        let value = match self {
            Uint8(uint8) => FWP_CONDITION_VALUE0_0 { uint8 },
            _ => {}
        };

        FWP_CONDTION_VALUE0 {
            r#type: typ,
            Anonymous: value,
        }
    }

    /// <https://learn.microsoft.com/en-us/windows/win32/api/fwptypes/ne-fwptypes-fwp_data_type>
    fn fwp_data_type(&self) -> FWP_DATA_TYPE0 {
        use ConditionValue::*;
        match self {
            Uint8(_) => FWP_UINT8,
            Uint16(_) => FWP_UINT16,
            Uint32(_) => FWP_UINT32,
            Uint64(_) => FWP_UINT64,
            Int8(_) => FWP_INT8,
            Int16(_) => FWP_INT16,
            Int32(_) => FWP_INT32,
            Int64(_) => FWP_INT64,
            Float(_) => FWP_FLOAT,
            Double(_) => FWP_DOUBLE,
            ByteArray16(_) => FWP_BYTE_ARRAY16_TYPE,
            Sid(_) => FWP_SID,
            ByteBlob(_) => FWP_BYTE_BLOB_TYPE,
            TokenInformation(_) => FWP_TOKEN_INFORMATION_TYPE,
            TokenAccessInformation(_) => FWP_TOKEN_ACCESS_INFORMATION_TYPE,
            V4AddrAndMask(_) => FWP_V4_ADDR_MASK,
            V6AddrAndMask(_) => FWP_V6_ADDR_MASK,
            RangeValue(_) => FWP_RANGE_TYPE,
        }
    }
}
