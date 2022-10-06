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
            let peer_id0 = "1AXRDqR8jTkwzGqyu3qknicAC5X578zTMxhAi2brppK2bB"
                .parse::<PeerId>()
                .unwrap();
            let peer_id1 = "1Ag5LvC3vwsQicTy1dxNdd1xiNxLUS4Aic4NtdHBqAHD3j"
                .parse::<PeerId>()
                .unwrap();
            Ok(vec![peer_id0, peer_id1])
        });
        Ok(mock_p2p)
    });
    api
}

fn register_fixtures() -> FixtureRegistry {
    [("peer_ids".to_string(), fixture_peer_ids as GetFixture)]
        .into_iter()
        .collect()
}

pub fn get_fixture_api() -> MockApi {
    let registry = register_fixtures();
    let fixture_name = env::var("IROH_CTL_FIXTURE").expect("IROH_CTL_FIXTURE must be set");
    let fixture = registry
        .get(&fixture_name)
        .unwrap_or_else(|| panic!("unknown fixture: {}", fixture_name));
    fixture()
}
