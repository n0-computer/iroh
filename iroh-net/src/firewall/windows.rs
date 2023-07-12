//! Windows firewall integration.
//!

use anyhow::Result;
use windows::{
    core::GUID,
    Win32::NetworkManagement::WindowsFilteringPlatform::{
        FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_FLAGS, FWPM_CONDITION_IP_LOCAL_PORT,
        FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS,
        FWPM_CONDITION_IP_REMOTE_PORT, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    },
};

use super::fwpm::{
    Action, ConditionFlag, ConditionValue, Engine, FilterCondition, IpProto, MatchType, Provider,
    Rule, Sublayer,
};

/// Handle to apply rules using the Windows Filtering Platform (Fwpm).
#[derive(Debug)]
pub struct Firewall {
    session: Engine,
    provider_id: GUID,
    sublayer_id: GUID,
}

const WEIGHT_IROH_TRAFFIC: u16 = 15;
const WEIGHT_KNOWN_TRAFFIC: u16 = 12;

impl Firewall {
    pub fn new() -> Result<Self> {
        let engine = Engine::new("Iroh firewall", "rules for iroh-net", true)?;
        let provider_id = GUID::new()?;
        engine.add_provider(Provider::new(provider_id, "Iroh provider")?)?;
        let sublayer_id = GUID::new()?;
        engine.add_sublayer(Sublayer::new(
            sublayer_id,
            "Iroh permissive and blocking filters",
            0,
        )?)?;

        let this = Firewall {
            session: engine,
            provider_id,
            sublayer_id,
        };

        this.enable()?;
        Ok(this)
    }

    fn enable(&self) -> Result<()> {
        self.permit_iroh_service()?;
        self.permit_dns()?;
        self.permit_loopback()?;
        self.permit_ndp()?;

        // TODO: do we want to do blockall, like tailscale?

        Ok(())
    }

    fn permit_iroh_service(&self) -> Result<()> {
        let current_executable = std::env::current_exe()?;
        let app_id = ConditionValue::app_id(current_executable)?;

        let conditions = [FilterCondition {
            field_key: FWPM_CONDITION_ALE_APP_ID,
            match_type: MatchType::Equal,
            condition_value: app_id,
        }];

        self.add_rules(
            "unrestricted traffic for Iroh service",
            WEIGHT_IROH_TRAFFIC,
            &conditions,
            Action::Permit,
            Protocol::All,
            Direction::Both,
        )?;

        Ok(())
    }

    fn permit_loopback(&self) -> Result<()> {
        let conditions = [FilterCondition {
            field_key: FWPM_CONDITION_FLAGS,
            match_type: MatchType::FlagsAllSet,
            condition_value: ConditionFlag::IsLoopback.into(),
        }];
        self.add_rules(
            "on loopback",
            WEIGHT_IROH_TRAFFIC,
            &conditions,
            Action::Permit,
            Protocol::All,
            Direction::Both,
        )?;

        Ok(())
    }

    fn permit_ndp(&self) -> Result<()> {
        let weight = WEIGHT_KNOWN_TRAFFIC;

        // These are aliased according to:
        // https://social.msdn.microsoft.com/Forums/azure/en-US/eb2aa3cd-5f1c-4461-af86-61e7d43ccc23/filtering-icmp-by-type-code?forum=wfp
        let field_icmp_type = FWPM_CONDITION_IP_LOCAL_PORT;
        let field_icmp_code = FWPM_CONDITION_IP_REMOTE_PORT;

        let icmp_conditions = |t, c, remote_address: Option<_>| {
            let mut conditions = vec![
                FilterCondition {
                    field_key: FWPM_CONDITION_IP_PROTOCOL,
                    match_type: MatchType::Equal,
                    condition_value: IpProto::IcmpV6.into(),
                },
                FilterCondition {
                    field_key: field_icmp_type,
                    match_type: MatchType::Equal,
                    condition_value: ConditionValue::Uint8(t),
                },
                FilterCondition {
                    field_key: field_icmp_code,
                    match_type: MatchType::Equal,
                    condition_value: ConditionValue::Uint8(c),
                },
            ];
            if remote_address.is_some() {
                conditions.push(FilterCondition {
                    field_key: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    match_type: MatchType::Equal,
                    condition_value: ConditionValue::from_v6_mask(LINK_LOCAL_ROUTER_MULTICAST)?,
                })
            }
            anyhow::Ok(conditions)
        };

        // Router Solicitation Message - ICMP type 133, code 0. Outgoing.
        let conditions = icmp_conditions(
            133,
            0,
            Some(ConditionValue::from_v6_mask(LINK_LOCAL_ROUTER_MULTICAST)?),
        )?;
        self.add_rules(
            "NDP type 133",
            weight,
            &conditions,
            Action::Permit,
            Protocol::IpV6,
            Direction::Outbound,
        )?;

        // Router Advertisement Message - ICMP type 134, code 0. Incoming.
        let conditions = icmp_conditions(
            134,
            0,
            Some(ConditionValue::from_v6_mask(LINK_LOCAL_RANGE)?),
        )?;
        self.add_rules(
            "NDP type 134",
            weight,
            &conditions,
            Action::Permit,
            Protocol::IpV6,
            Direction::Inbound,
        )?;

        // Neighbor Solicitation Message - ICMP type 135, code 0. Bi-directional.
        let conditions = icmp_conditions(135, 0, None)?;
        self.add_rules(
            "NDP type 135",
            weight,
            &conditions,
            Action::Permit,
            Protocol::IpV6,
            Direction::Both,
        )?;

        // Neighbor Advertisement Message - ICMP type 136, code 0. Bi-directional.
        let conditions = icmp_conditions(136, 0, None)?;
        self.add_rules(
            "NDP type 136",
            weight,
            &conditions,
            Action::Permit,
            Protocol::IpV6,
            Direction::Both,
        )?;

        // Redirect Message - ICMP type 137, code 0. Incoming.
        let conditions = icmp_conditions(
            137,
            0,
            Some(ConditionValue::from_v6_mask(LINK_LOCAL_RANGE)?),
        )?;
        self.add_rules(
            "NDP type 137",
            weight,
            &conditions,
            Action::Permit,
            Protocol::IpV6,
            Direction::Inbound,
        )?;

        Ok(())
    }

    fn permit_dns(&self) -> Result<()> {
        let conditions = [
            FilterCondition {
                field_key: FWPM_CONDITION_IP_REMOTE_PORT,
                match_type: MatchType::Equal,
                condition_value: ConditionValue::Uint16(53),
            },
            // Repeat the condition type for logical OR.
            FilterCondition {
                field_key: FWPM_CONDITION_IP_PROTOCOL,
                match_type: MatchType::Equal,
                condition_value: IpProto::Udp.into(),
            },
            FilterCondition {
                field_key: FWPM_CONDITION_IP_PROTOCOL,
                match_type: MatchType::Equal,
                condition_value: IpProto::Tcp.into(),
            },
        ];
        self.add_rules(
            "DNS",
            WEIGHT_IROH_TRAFFIC,
            &conditions,
            Action::Permit,
            Protocol::All,
            Direction::Both,
        )?;
        Ok(())
    }

    fn add_rules(
        &self,
        name: &str,
        weight: u16,
        conditions: &[FilterCondition],
        action: Action,
        protocol: Protocol,
        direction: Direction,
    ) -> Result<()> {
        for layer in protocol.layers(direction) {
            let rule = self.new_rule(name, weight, layer, conditions, action)?;
            self.session.add_rule(rule)?;
        }

        Ok(())
    }

    fn new_rule(
        &self,
        name: &str,
        weight: u16,
        layer: GUID,
        conditions: &[FilterCondition],
        action: Action,
    ) -> Result<Rule> {
        let name = rule_name(action, layer, name);
        let mut rule = Rule::new(&name, layer, self.sublayer_id, u64::from(weight), action)?;
        rule.provider = Some(self.provider_id);
        rule.conditions.extend_from_slice(conditions);

        Ok(rule)
    }
}

/// Protocol.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Protocol {
    IpV4,
    IpV6,
    All,
}

impl Protocol {
    /// Returns the layer IDs based on the given protocol and direction combination.
    fn layers(self, direction: Direction) -> Vec<GUID> {
        let mut layers = Vec::new();

        if self == Protocol::All || self == Protocol::IpV4 {
            if direction == Direction::Both || direction == Direction::Inbound {
                layers.push(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4);
            }
            if direction == Direction::Both || direction == Direction::Outbound {
                layers.push(FWPM_LAYER_ALE_AUTH_CONNECT_V4);
            }
        }

        if self == Protocol::All || self == Protocol::IpV6 {
            if direction == Direction::Both || direction == Direction::Inbound {
                layers.push(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6);
            }
            if direction == Direction::Both || direction == Direction::Outbound {
                layers.push(FWPM_LAYER_ALE_AUTH_CONNECT_V6);
            }
        }

        layers
    }
}

fn rule_name(action: Action, layer_id: GUID, name: &str) -> String {
    match layer_id {
        FWPM_LAYER_ALE_AUTH_CONNECT_V4 => {
            format!("{action} outbound {name} (IPv4)")
        }
        FWPM_LAYER_ALE_AUTH_CONNECT_V6 => {
            format!("{action} outbound {name} (IPv6)")
        }
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 => {
            format!("{action} inbound {name} (IPv4)")
        }
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 => {
            format!("{action} inbound {name} (IPv6)")
        }
        _ => format!("{action} - {name} - {layer_id:?}"),
    }
}

/// Traffic direction.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Direction {
    Inbound,
    Outbound,
    Both,
}

// Known Addresses

const LINK_LOCAL_RANGE: &str = "ff80::/10";
const LINK_LOCAL_DHCP_MULTICAST: &str = "ff02::1:2";
const LINK_LOCAL_ROUTER_MULTICAST: &str = "ff02::2";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basics() {
        let engine = Firewall::new().unwrap();
        println!("{engine:?}");
    }
}
