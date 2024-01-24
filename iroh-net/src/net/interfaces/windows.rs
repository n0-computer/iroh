use std::collections::HashMap;

use serde::Deserialize;
use tracing::warn;
use wmi::{query::FilterValue, COMLibrary, WMIConnection};

use super::DefaultRouteDetails;

/// API Docs: <https://learn.microsoft.com/en-us/previous-versions/windows/desktop/wmiiprouteprov/win32-ip4routetable>
#[derive(Deserialize, Debug)]
#[allow(non_camel_case_types, non_snake_case)]
struct Win32_IP4RouteTable {
    Name: String,
    InterfaceIndex: i64,
    Description: String,
}

fn get_default_route() -> anyhow::Result<DefaultRouteDetails> {
    let com_con = COMLibrary::new()?;
    let wmi_con = WMIConnection::new(com_con.into())?;

    let query: HashMap<_, _> = [("Destination".into(), FilterValue::Str("0.0.0.0"))].into();
    let route: Win32_IP4RouteTable = wmi_con
        .filtered_query(&query)?
        .drain(..)
        .next()
        .ok_or_else(|| anyhow::anyhow!("no route found"))?;

    let idx = route.InterfaceIndex.try_into()?;

    Ok(DefaultRouteDetails {
        interface_index: idx,
        interface_name: route.Name,
        interface_description: Some(route.Description),
    })
}

pub async fn default_route() -> Option<DefaultRouteDetails> {
    match get_default_route() {
        Ok(route) => Some(route),
        Err(err) => {
            warn!("failed to retrieve default route: {:#?}", err);
            None
        }
    }
}
