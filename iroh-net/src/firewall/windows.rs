//! Windows firewall integration.
//!

use anyhow::Result;
use windows::core::GUID;

use super::fwpm::{Engine, Provider, Sublayer, FilterCondition};

/// Handle to apply rules using the Windows Filtering Platform (Fwpm).
#[derive(Debug)]
pub struct Firewall {
    session: Engine,
    provider_id: GUID,
    sublayer_id: GUID,
}

const WEIGHT_IROH_TRAFFIC: u16 = 15;

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
        Ok(())
    }

    fn permit_iroh_service(&self) -> Result<()> {
        // TODO:

        Ok(())
    }

    fn permit_dns(&self) -> Result<()> {
        // let conditions = [
        //     FilterCondition {
        //         field: FieldId::IpRemotePort,
        //         op: MatchType::Equal,
        //         value: MatchValue::U16(53),
        //     },
        //     // Repeat the condition type for logical OR.
        //     FilterCondition {
        //         field: FieldId::IpProtocol,
        //         op: MatchType::Equal,
        //         value: MatchValue::IpProtoUdp,
        //     },
        //     FilterCondition {
        //         field: FieldId::IpProtocol,
        //         op: MatchType::Equal,
        //         value: MatchValue::IpProtoTcp,
        //     },
        // ];
        // self.add_rules(
        //     "DNS",
        //     WEIGHT_IROH_TRAFFIC,
        //     conditions,
        //     Action::Permit,
        //     protocolAll,
        //     directionBoth,
        // )?;
        Ok(())
    }

    // fn add_rules(&self, name: &str, )
}
