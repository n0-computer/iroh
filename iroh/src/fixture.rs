use std::collections::HashMap;
use std::env;
use std::future;
use std::path::PathBuf;
use std::str::FromStr;

use futures::StreamExt;
use iroh_api::{AddEvent, Cid, Lookup, MockApi, MockP2p, OutType, PeerId};
use relative_path::RelativePathBuf;

type GetFixture = fn() -> MockApi;
type FixtureRegistry = HashMap<String, GetFixture>;

fn fixture_lookup() -> MockApi {
    let mut api = MockApi::default();
    api.expect_p2p().returning(|| {
        let mut mock_p2p = MockP2p::default();

        mock_p2p.expect_lookup().returning(|_addr| {
            let peer_id = "1AXRDqR8jTkwzGqyu3qknicAC5X578zTMxhAi2brppK2bB"
                .parse::<PeerId>()
                .unwrap();
            Ok(Lookup {
                peer_id,
                listen_addrs: vec![],
                observed_addrs: vec![],
                agent_version: String::new(),
                protocols: vec![],
                protocol_version: String::new(),
            })
        });
        Ok(mock_p2p)
    });
    api
}

fn fixture_get() -> MockApi {
    let mut api = MockApi::default();
    api.expect_get_stream().returning(|_ipfs_path| {
        futures::stream::iter(vec![
            Ok((RelativePathBuf::from_path("").unwrap(), OutType::Dir)),
            Ok((RelativePathBuf::from_path("a").unwrap(), OutType::Dir)),
            // git doesn't like empty directories, nor does trycmd trip if it's missing
            // we rely on the unit test for save_get_stream elsewhere to check empty
            // directories are created
            Ok((
                RelativePathBuf::from_path("a/exists").unwrap(),
                OutType::Symlink(PathBuf::from("../b")),
            )),
            Ok((
                RelativePathBuf::from_path("b").unwrap(),
                OutType::Reader(Box::new(std::io::Cursor::new("hello"))),
            )),
        ])
        .boxed_local()
    });
    api
}

fn fixture_add_file() -> MockApi {
    let mut api = MockApi::default();
    api.expect_add_file().returning(|_ipfs_path, _| {
        let cid = Cid::from_str("QmYbcW4tXLXHWw753boCK8Y7uxLu5abXjyYizhLznq9PUR").unwrap();
        let add_event = AddEvent::ProgressDelta { cid, size: Some(0) };

        Box::pin(future::ready(Ok(futures::stream::iter(vec![Ok(
            add_event,
        )])
        .boxed_local())))
    });
    api
}

fn fixture_add_directory() -> MockApi {
    let mut api = MockApi::default();
    api.expect_add_dir().returning(|_ipfs_path, _| {
        let cid = Cid::from_str("QmYbcW4tXLXHWw753boCK8Y7uxLu5abXjyYizhLznq9PUR").unwrap();
        let add_event = AddEvent::ProgressDelta { cid, size: Some(0) };

        Box::pin(future::ready(Ok(futures::stream::iter(vec![Ok(
            add_event,
        )])
        .boxed_local())))
    });
    api
}

fn fixture_get_wrapped_file() -> MockApi {
    let mut api = MockApi::default();
    api.expect_get_stream().returning(|_ipfs_path| {
        futures::stream::iter(vec![
            Ok((RelativePathBuf::from_path("").unwrap(), OutType::Dir)),
            Ok((
                RelativePathBuf::from_path("file.txt").unwrap(),
                OutType::Reader(Box::new(std::io::Cursor::new("hello"))),
            )),
        ])
        .boxed_local()
    });
    api
}

fn fixture_get_unwrapped_file() -> MockApi {
    let mut api = MockApi::default();
    api.expect_get_stream().returning(|_ipfs_path| {
        futures::stream::iter(vec![Ok((
            RelativePathBuf::from_path("").unwrap(),
            OutType::Reader(Box::new(std::io::Cursor::new("hello"))),
        ))])
        .boxed_local()
    });
    api
}

fn fixture_get_wrapped_symlink() -> MockApi {
    let mut api = MockApi::default();
    api.expect_get_stream().returning(|_ipfs_path| {
        futures::stream::iter(vec![
            Ok((RelativePathBuf::from_path("").unwrap(), OutType::Dir)),
            Ok((
                RelativePathBuf::from_path("symlink.txt").unwrap(),
                OutType::Symlink(PathBuf::from("target/path/foo.txt")),
            )),
        ])
        .boxed_local()
    });
    api
}

fn fixture_get_unwrapped_symlink() -> MockApi {
    let mut api = MockApi::default();
    api.expect_get_stream().returning(|_ipfs_path| {
        futures::stream::iter(vec![Ok((
            RelativePathBuf::from_path("").unwrap(),
            OutType::Symlink(PathBuf::from("target/path/foo.txt")),
        ))])
        .boxed_local()
    });
    api
}

fn register_fixtures() -> FixtureRegistry {
    [
        ("lookup".to_string(), fixture_lookup as GetFixture),
        ("get".to_string(), fixture_get as GetFixture),
        (
            "get_wrapped_file".to_string(),
            fixture_get_wrapped_file as GetFixture,
        ),
        (
            "get_unwrapped_file".to_string(),
            fixture_get_unwrapped_file as GetFixture,
        ),
        ("add_file".to_string(), fixture_add_file as GetFixture),
        (
            "add_directory".to_string(),
            fixture_add_directory as GetFixture,
        ),
        (
            "get_wrapped_symlink".to_string(),
            fixture_get_wrapped_symlink as GetFixture,
        ),
        (
            "get_unwrapped_symlink".to_string(),
            fixture_get_unwrapped_symlink as GetFixture,
        ),
    ]
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
