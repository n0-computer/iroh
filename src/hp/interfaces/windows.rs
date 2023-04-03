use std::collections::HashMap;

use serde::Deserialize;
use wmi::{query::FilterValue, COMLibrary, WMIConnection};

use super::DefaultRouteDetails;

fn default_route_interface_index() -> Option<u32> {
    let com_con = COMLibrary::new()?;
    let wmi_con = WMIConnection::new(com_con.into())?;

    #[derive(Deserialize, Debug)]
    #[allow(non_camel_case_types, non_snake_case)]
    struct Win32_IP4RouteTable {
        InterfaceIndex: i64,
    }

    let query: HashMap<_, _> = [("Destination".into(), FilterValue::Str("0.0.0.0"))].into();
    let route: Win32_IP4RouteTable = wmi_con.filtered_query(&query)?.drain(..).next()?;

    println!("{:#?}", route);

    route.InterfaceIndex.try_into().ok()
}

pub fn default_route() -> Option<DefaultRouteDetails> {
    let idx = default_route_interface_index()?;
    let interfaces = default_net::get_interfaces();
    dbg!(interfaces);
    let iface = interfaces.into_iter().find(|i| i.index == idx)?;

    Some(DefaultRouteDetails {
        interface_index: idx,
        interface_name: iface.name,
        interface_description: None,
    })
}
