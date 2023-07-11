use widestring::U16CString;
use windows::{
    core::{GUID, PWSTR},
    Win32::{
        NetworkManagement::WindowsFilteringPlatform::{
            FWPM_DISPLAY_DATA0, FWPM_PROVIDER0, FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC,
            FWPM_SUBLAYER0, FWP_ACTION_FLAG_CALLOUT, FWP_ACTION_FLAG_NON_TERMINATING,
            FWP_ACTION_FLAG_TERMINATING, FWP_BYTE_ARRAY16, FWP_BYTE_ARRAY16_TYPE, FWP_BYTE_ARRAY6,
            FWP_BYTE_ARRAY6_TYPE, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0,
            FWP_CONDITION_VALUE0_0, FWP_DATA_TYPE, FWP_DOUBLE, FWP_FLOAT, FWP_INT16, FWP_INT32,
            FWP_INT64, FWP_INT8, FWP_MATCH_TYPE, FWP_RANGE0, FWP_RANGE_TYPE,
            FWP_SECURITY_DESCRIPTOR_TYPE, FWP_SID, FWP_TOKEN_ACCESS_INFORMATION_TYPE,
            FWP_TOKEN_INFORMATION, FWP_TOKEN_INFORMATION_TYPE, FWP_UINT16, FWP_UINT32, FWP_UINT64,
            FWP_UINT8, FWP_UNICODE_STRING_TYPE, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK,
            FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK,
        },
        Security::SID,
        System::Rpc::RPC_C_AUTHN_WINNT,
    },
};

/// Wrapper around `FWPM_FILTER0`
pub struct Rule {
    /// The unique identifier for this rule.
    pub id: GUID,
    /// The kernel ID for this rule.
    pub kernel_id: u64,
    /// A short descriptive name.
    pub name: U16CString,
    /// Longer description of the rule.
    pub description: U16CString,
    /// The ID of the layer in which the rule runs.
    pub layer: GUID,
    /// The ID of the sublayer in which the rule runs.
    pub sublayer: GUID,
    /// The priority of the rule relative to other rules in its sublayer.
    pub weight: u64,
    /// Conditions are the tests which must pass for this rule to apply to a packet.
    pub conditions: Vec<FilterCondition>,
    /// The action to take on matching packets.
    pub action: Action,
    /// The ID of the callout to invoke. Only valid if `action` is `Action::CalloutTerminating`,
    /// or `Action::CalloutInspection``, or `Action::CalloutUnknown`.
    pub callout: Option<GUID>,
    /// If set, indicates that a callout action to a callout ID that isn't registered should
    /// be translated into an `Action::Permit`, rather than an `Action::Block`. Only relevant if
    /// `action` is `Action::CalloutTerminating` or `Action::CalloutUnknown`.
    pub permit_if_missing: bool,
    /// If set, indicates that the action type is hard and cannot be overridden except by a Veto.
    pub hard_action: bool,
    /// ndicates whether the rule is preserved across restarts of the filtering engine.
    pub persistent: bool,
    /// Indicates that this rule applies only during early
    /// boot, before the filtering engine fully starts and hands off to the normal runtime rules.
    pub boot_time: bool,
    /// Optionally identifies the Provider that manages this rule.
    pub provider: Option<GUID>,
    /// Optional opaque data that can be held on behalf of the Provider.
    pub provider_data: Option<Vec<u8>>,
    /// Indicates whether the rule is currently disabled due
    /// to its provider being associated with an inactive Windows service.
    pub disabled: bool,
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
    CalloutInspection = 0x00000004 | FWP_ACTION_FLAG_CALLOUT | FWP_ACTION_FLAG_NON_TERMINATING,
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
    pub field_key: GUID,
    /// Specifies the type of match to be performed.
    pub match_type: MatchType,
    /// Contains the value to match the field against.
    pub condition_value: ConditionValue,
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

/// The poosible values that are used in filter conditions when testing for matching filters.
///
/// Wrapper around `FWPM_CONDTION_VALUE0_0`.
/// <https://learn.microsoft.com/en-us/windows/win32/api/fwptypes/ns-fwptypes-fwp_condition_value0>
pub enum ConditionValue {
    Uint8(u8),
    Uint16(u16),
    Uint32(u32),
    Uint64(u64),
    Int8(i8),
    Int16(i16),
    Int32(i32),
    Int64(i64),
    Float(f32),
    Double64(f64),
    ByteArray16(FWP_BYTE_ARRAY16),
    ByteBlob(FWP_BYTE_BLOB),
    Sid(SID),
    Sd(FWP_BYTE_BLOB),
    TokenInformation(FWP_TOKEN_INFORMATION),
    TokenAccessInformation(FWP_BYTE_BLOB),
    UnicodeString(PWSTR),
    ByteArray6(FWP_BYTE_ARRAY6),
    V4AddrAndMask(FWP_V4_ADDR_AND_MASK),
    V6AddrAndMask(FWP_V6_ADDR_AND_MASK),
    RangeValue(FWP_RANGE0),
}

impl ConditionValue {
    pub(super) unsafe fn as_fwp_condtion_value0(&mut self) -> FWP_CONDITION_VALUE0 {
        use ConditionValue::*;

        let typ = self.fwp_data_type();
        let value = match self {
            Uint8(val) => FWP_CONDITION_VALUE0_0 { uint8: *val },
            Uint16(val) => FWP_CONDITION_VALUE0_0 { uint16: *val },
            Uint32(val) => FWP_CONDITION_VALUE0_0 { uint32: *val },
            Uint64(val) => FWP_CONDITION_VALUE0_0 { uint64: &mut *val },
            Int8(val) => FWP_CONDITION_VALUE0_0 { int8: *val },
            Int16(val) => FWP_CONDITION_VALUE0_0 { int16: *val },
            Int32(val) => FWP_CONDITION_VALUE0_0 { int32: *val },
            Int64(val) => FWP_CONDITION_VALUE0_0 { int64: &mut *val },
            Float(val) => FWP_CONDITION_VALUE0_0 { float32: *val },
            Double64(val) => FWP_CONDITION_VALUE0_0 {
                double64: &mut *val,
            },
            ByteArray16(val) => FWP_CONDITION_VALUE0_0 {
                byteArray16: &mut *val,
            },
            ByteBlob(val) => FWP_CONDITION_VALUE0_0 {
                byteBlob: &mut *val,
            },
            Sid(val) => FWP_CONDITION_VALUE0_0 { sid: &mut *val },
            Sd(val) => FWP_CONDITION_VALUE0_0 { sd: &mut *val },
            TokenInformation(val) => FWP_CONDITION_VALUE0_0 {
                tokenInformation: &mut *val,
            },
            TokenAccessInformation(val) => FWP_CONDITION_VALUE0_0 {
                tokenAccessInformation: &mut *val,
            },
            UnicodeString(val) => FWP_CONDITION_VALUE0_0 {
                unicodeString: *val,
            },
            ByteArray6(val) => FWP_CONDITION_VALUE0_0 {
                byteArray6: &mut *val,
            },
            V4AddrAndMask(val) => FWP_CONDITION_VALUE0_0 {
                v4AddrMask: &mut *val,
            },
            V6AddrAndMask(val) => FWP_CONDITION_VALUE0_0 {
                v6AddrMask: &mut *val,
            },
            RangeValue(val) => FWP_CONDITION_VALUE0_0 {
                rangeValue: &mut *val,
            },
        };

        FWP_CONDITION_VALUE0 {
            r#type: typ,
            Anonymous: value,
        }
    }

    /// <https://learn.microsoft.com/en-us/windows/win32/api/fwptypes/ne-fwptypes-fwp_data_type>
    fn fwp_data_type(&self) -> FWP_DATA_TYPE {
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
            Double64(_) => FWP_DOUBLE,
            ByteArray16(_) => FWP_BYTE_ARRAY16_TYPE,
            Sid(_) => FWP_SID,
            Sd(_) => FWP_SECURITY_DESCRIPTOR_TYPE,
            ByteBlob(_) => FWP_BYTE_BLOB_TYPE,
            TokenInformation(_) => FWP_TOKEN_INFORMATION_TYPE,
            TokenAccessInformation(_) => FWP_TOKEN_ACCESS_INFORMATION_TYPE,
            UnicodeString(_) => FWP_UNICODE_STRING_TYPE,
            ByteArray6(_) => FWP_BYTE_ARRAY6_TYPE,
            V4AddrAndMask(_) => FWP_V4_ADDR_MASK,
            V6AddrAndMask(_) => FWP_V6_ADDR_MASK,
            RangeValue(_) => FWP_RANGE_TYPE,
        }
    }
}
