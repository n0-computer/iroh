use std::collections::HashMap;
use std::env;

use iroh::{MockApi, MockP2p};
use libp2p::PeerId;

type GetFixture = fn() -> MockApi;
type FixtureRegistry = HashMap<String, GetFixture>;

fn fixture_peer_ids() -> MockApi {
    let mut api = MockApi::default();
    api.expect_p2p().returning(|| {
        let mut mock_p2p = MockP2p::default();

        mock_p2p.expect_peer_ids().returning(|| {
            let peer_id0 = PeerId::from_bytes(&[
                0, 32, 15, 231, 162, 148, 52, 155, 40, 187, 217, 170, 125, 185, 68, 142, 156, 196,
                145, 178, 64, 74, 19, 27, 9, 171, 111, 35, 88, 236, 103, 150, 96, 66,
            ])?;
            let peer_id1 = PeerId::from_bytes(&[
                0, 32, 144, 137, 53, 144, 57, 13, 191, 157, 254, 110, 136, 212, 131, 241, 179, 29,
                38, 29, 207, 62, 126, 215, 213, 49, 248, 43, 143, 40, 123, 93, 248, 222,
            ])?;
            Ok(vec![peer_id0, peer_id1])
        });
        Ok(mock_p2p)
    });
    api
}

fn register_fixtures() -> FixtureRegistry {
    let mut registry = FixtureRegistry::new();
    registry.insert("peer_ids".to_string(), fixture_peer_ids);
    registry
}

pub fn get_fixture_api() -> MockApi {
    let registry = register_fixtures();
    let fixture_name = env::var("IROH_CTL_FIXTURE").expect("IROH_CTL_FIXTURE must be set");
    let fixture = registry
        .get(&fixture_name)
        .unwrap_or_else(|| panic!("unknown fixture: {}", fixture_name));
    fixture()
}
