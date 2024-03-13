use bao_tree::ChunkRanges;
use iroh_io::AsyncSliceReaderExt;
use std::io::Cursor;
use std::time::Duration;

use crate::store::bao_file::raw_outboard;
use crate::store::bao_file::test_support::{
    decode_response_into_batch, make_wire_data, random_test_data, simulate_remote, validate,
};
use crate::store::{Map as _, MapEntryMut, MapMut, Store as _};

macro_rules! assert_matches {
        ($expression:expr, $pattern:pat) => {
            match $expression {
                $pattern => (),
                _ => panic!("assertion failed: `(expr matches pattern)` \
                             expression: `{:?}`, pattern: `{}`", $expression, stringify!($pattern)),
            }
        };
        ($expression:expr, $pattern:pat, $($arg:tt)+) => {
            match $expression {
                $pattern => (),
                _ => panic!("{}: expression: `{:?}`, pattern: `{}`", format_args!($($arg)+), $expression, stringify!($pattern)),
            }
        };
    }

use super::*;

/// Helper to simulate a slow request.
pub fn to_stream(
    data: &[u8],
    mtu: usize,
    delay: std::time::Duration,
) -> impl Stream<Item = io::Result<Bytes>> + 'static {
    let parts = data
        .chunks(mtu)
        .map(Bytes::copy_from_slice)
        .collect::<Vec<_>>();
    futures::stream::iter(parts)
        .then(move |part| async move {
            tokio::time::sleep(delay).await;
            io::Result::Ok(part)
        })
        .boxed()
}

async fn create_test_db() -> (tempfile::TempDir, Store) {
    let _ = tracing_subscriber::fmt::try_init();
    let testdir = tempfile::tempdir().unwrap();
    let db_path = testdir.path().join("db.redb");
    let options = Options {
        path: PathOptions::new(testdir.path()),
        inline: Default::default(),
    };
    let db = Store::new(db_path, options).await.unwrap();
    (testdir, db)
}

/// small file that does not have outboard at all
const SMALL_SIZE: u64 = 1024;
/// medium file that has inline outboard but file data
const MID_SIZE: u64 = 1024 * 32;
/// large file that has file outboard and file data
const LARGE_SIZE: u64 = 1024 * 1024 * 10;

#[tokio::test]
async fn get_cases() {
    let np = IgnoreProgressSender::<ImportProgress>::default;
    let (tempdir, db) = create_test_db().await;
    {
        let small = Bytes::from(random_test_data(SMALL_SIZE as usize));
        let (_outboard, hash) = raw_outboard(&small);
        let res = db.get(&hash).await.unwrap();
        assert_matches!(res, None);
        let tt = db
            .import_bytes(small.clone(), BlobFormat::Raw)
            .await
            .unwrap();
        let res = db.get(&hash).await.unwrap();
        let entry = res.expect("entry not found");
        let actual = entry
            .data_reader()
            .await
            .unwrap()
            .read_to_end()
            .await
            .unwrap();
        assert_eq!(actual, small);
        drop(tt);
    }
    {
        let mid = Bytes::from(random_test_data(MID_SIZE as usize));
        let (_outboard, hash) = raw_outboard(&mid);
        let res = db.get(&hash).await.unwrap();
        assert_matches!(res, None);
        let tt = db.import_bytes(mid.clone(), BlobFormat::Raw).await.unwrap();
        let res = db.get(&hash).await.unwrap();
        let entry = res.expect("entry not found");
        let actual = entry
            .data_reader()
            .await
            .unwrap()
            .read_to_end()
            .await
            .unwrap();
        assert_eq!(actual, mid);
        drop(tt);
    }
    {
        let large = Bytes::from(random_test_data(LARGE_SIZE as usize));
        let (_outboard, hash) = raw_outboard(&large);
        let res = db.get(&hash).await.unwrap();
        assert_matches!(res, None);
        let tt = db
            .import_bytes(large.clone(), BlobFormat::Raw)
            .await
            .unwrap();
        let res = db.get(&hash).await.unwrap();
        let entry = res.expect("entry not found");
        let actual = entry
            .data_reader()
            .await
            .unwrap()
            .read_to_end()
            .await
            .unwrap();
        assert_eq!(actual, large);
        drop(tt);
    }
    {
        let mid = random_test_data(MID_SIZE as usize);
        let path = tempdir.path().join("mid.data");
        std::fs::write(&path, &mid).unwrap();
        let (_outboard, hash) = raw_outboard(&mid);
        let res = db.get(&hash).await.unwrap();
        assert_matches!(res, None);
        let tt = db
            .import_file(path, ImportMode::TryReference, BlobFormat::Raw, np())
            .await
            .unwrap();
        let res = db.get(&hash).await.unwrap();
        let entry = res.expect("entry not found");
        let actual = entry
            .data_reader()
            .await
            .unwrap()
            .read_to_end()
            .await
            .unwrap();
        assert_eq!(actual, mid);
        drop(tt);
    }
}

#[tokio::test]
async fn get_or_create_cases() {
    let (_tempdir, db) = create_test_db().await;
    {
        const SIZE: u64 = SMALL_SIZE;
        let data = random_test_data(SIZE as usize);
        let (hash, reader) = simulate_remote(&data);
        let entry = db.get_or_create(hash, 0).await.unwrap();
        {
            let state = db.entry_state(hash).await.unwrap();
            assert_eq!(state.db, None);
            assert_matches!(state.mem, Some(_));
        }
        let writer = entry.batch_writer().await.unwrap();
        decode_response_into_batch(hash, IROH_BLOCK_SIZE, ChunkRanges::all(), reader, writer)
            .await
            .unwrap();
        {
            let state = db.entry_state(hash).await.unwrap();
            assert_matches!(state.mem, Some(_));
            assert_matches!(state.db, None);
        }
        db.insert_complete(entry.clone()).await.unwrap();
        {
            let state = db.entry_state(hash).await.unwrap();
            assert_matches!(state.mem, Some(_));
            assert_matches!(
                state.db,
                Some(EntryState::Complete {
                    data_location: DataLocation::Inline(_),
                    ..
                })
            );
        }
        drop(entry);
        // sync so we know the msg sent on drop is processed
        db.sync().await.unwrap();
        let state = db.entry_state(hash).await.unwrap();
        assert_matches!(state.mem, None);
    }
    {
        const SIZE: u64 = MID_SIZE;
        let data = random_test_data(SIZE as usize);
        let (hash, reader) = simulate_remote(&data);
        let entry = db.get_or_create(hash, 0).await.unwrap();
        {
            let state = db.entry_state(hash).await.unwrap();
            assert_eq!(state.db, None);
            assert_matches!(state.mem, Some(_));
        }
        let writer = entry.batch_writer().await.unwrap();
        decode_response_into_batch(hash, IROH_BLOCK_SIZE, ChunkRanges::all(), reader, writer)
            .await
            .unwrap();
        {
            let state = db.entry_state(hash).await.unwrap();
            assert_matches!(state.mem, Some(_));
            assert_matches!(state.db, Some(EntryState::Partial { .. }));
        }
        db.insert_complete(entry.clone()).await.unwrap();
        {
            let state = db.entry_state(hash).await.unwrap();
            assert_matches!(state.mem, Some(_));
            assert_matches!(
                state.db,
                Some(EntryState::Complete {
                    data_location: DataLocation::Owned(SIZE),
                    ..
                })
            );
        }
        drop(entry);
        // // sync so we know the msg sent on drop is processed
        // db.sync().await.unwrap();
        // let state = db.entry_state(hash).await.unwrap();
        // assert_matches!(state.mem, None);
    }
}

/// Import mem cases, small (data inline, outboard none), mid (data file, outboard inline), large (data file, outboard file)
#[tokio::test]
async fn import_mem_cases() {
    let (_tempdir, db) = create_test_db().await;
    {
        const SIZE: u64 = SMALL_SIZE;
        let small = Bytes::from(random_test_data(SIZE as usize));
        let (outboard, hash) = raw_outboard(&small);
        let tt = db
            .import_bytes(small.clone(), BlobFormat::Raw)
            .await
            .unwrap();
        let actual = db.entry_state(*tt.hash()).await.unwrap();
        let expected = EntryState::Complete {
            data_location: DataLocation::Inline(small),
            outboard_location: OutboardLocation::NotNeeded,
        };
        assert_eq!(tt.hash(), &hash);
        assert_eq!(actual.db, Some(expected));
        assert!(outboard.is_empty());
    }
    {
        const SIZE: u64 = MID_SIZE;
        let mid = Bytes::from(random_test_data(SIZE as usize));
        let (outboard, hash) = raw_outboard(&mid);
        let tt = db.import_bytes(mid.clone(), BlobFormat::Raw).await.unwrap();
        let actual = db.entry_state(*tt.hash()).await.unwrap();
        let expected = EntryState::<Bytes>::Complete {
            data_location: DataLocation::Owned(SIZE),
            outboard_location: OutboardLocation::Inline(Bytes::from(outboard)),
        };
        assert_eq!(tt.hash(), &hash);
        assert_eq!(actual.db, Some(expected));
        assert_eq!(mid, std::fs::read(db.owned_data_path(&hash)).unwrap());
    }
    {
        const SIZE: u64 = LARGE_SIZE;
        let large = Bytes::from(random_test_data(SIZE as usize));
        let (outboard, hash) = raw_outboard(&large);
        let tt = db
            .import_bytes(large.clone(), BlobFormat::Raw)
            .await
            .unwrap();
        let actual = db.entry_state(*tt.hash()).await.unwrap();
        let expected = EntryState::<Bytes>::Complete {
            data_location: DataLocation::Owned(SIZE),
            outboard_location: OutboardLocation::Owned,
        };
        assert_eq!(tt.hash(), &hash);
        assert_eq!(actual.db, Some(expected));
        assert_eq!(large, std::fs::read(db.owned_data_path(&hash)).unwrap());
        assert_eq!(
            outboard,
            tokio::fs::read(db.owned_outboard_path(&hash))
                .await
                .unwrap()
        );
    }
}

/// Import mem cases, small (data inline, outboard none), mid (data file, outboard inline), large (data file, outboard file)
#[tokio::test]
async fn import_stream_cases() {
    let np = IgnoreProgressSender::<ImportProgress>::default;
    let (_tempdir, db) = create_test_db().await;
    {
        const SIZE: u64 = SMALL_SIZE;
        let small = Bytes::from(random_test_data(SIZE as usize));
        let (outboard, hash) = raw_outboard(&small);
        let (tt, size) = db
            .import_stream(
                to_stream(&small, 100, Duration::from_millis(1)),
                BlobFormat::Raw,
                np(),
            )
            .await
            .unwrap();
        let actual = db.entry_state(*tt.hash()).await.unwrap();
        let expected = EntryState::Complete {
            data_location: DataLocation::Inline(small),
            outboard_location: OutboardLocation::NotNeeded,
        };
        assert_eq!(size, SIZE);
        assert_eq!(tt.hash(), &hash);
        assert_eq!(actual.db, Some(expected));
        assert!(outboard.is_empty());
    }
    {
        const SIZE: u64 = MID_SIZE;
        let mid = Bytes::from(random_test_data(SIZE as usize));
        let (outboard, hash) = raw_outboard(&mid);
        let (tt, size) = db
            .import_stream(
                to_stream(&mid, 1000, Duration::from_millis(1)),
                BlobFormat::Raw,
                np(),
            )
            .await
            .unwrap();
        let actual = db.entry_state(*tt.hash()).await.unwrap();
        let expected = EntryState::<Bytes>::Complete {
            data_location: DataLocation::Owned(SIZE),
            outboard_location: OutboardLocation::Inline(Bytes::from(outboard)),
        };
        assert_eq!(size, SIZE);
        assert_eq!(tt.hash(), &hash);
        assert_eq!(actual.db, Some(expected));
        assert_eq!(mid, std::fs::read(db.owned_data_path(&hash)).unwrap());
    }
    {
        const SIZE: u64 = LARGE_SIZE;
        let large = Bytes::from(random_test_data(SIZE as usize));
        let (outboard, hash) = raw_outboard(&large);
        let (tt, size) = db
            .import_stream(
                to_stream(&large, 100000, Duration::from_millis(1)),
                BlobFormat::Raw,
                np(),
            )
            .await
            .unwrap();
        let actual = db.entry_state(*tt.hash()).await.unwrap();
        let expected = EntryState::<Bytes>::Complete {
            data_location: DataLocation::Owned(SIZE),
            outboard_location: OutboardLocation::Owned,
        };
        assert_eq!(size, SIZE);
        assert_eq!(tt.hash(), &hash);
        assert_eq!(actual.db, Some(expected));
        assert_eq!(large, std::fs::read(db.owned_data_path(&hash)).unwrap());
        assert_eq!(
            outboard,
            tokio::fs::read(db.owned_outboard_path(&hash))
                .await
                .unwrap()
        );
    }
}

/// Import file cases, small (data inline, outboard none), mid (data file, outboard inline), large (data file, outboard file)
#[tokio::test]
async fn import_file_cases() {
    let np = IgnoreProgressSender::<ImportProgress>::default;
    let (tempdir, db) = create_test_db().await;
    {
        const SIZE: u64 = SMALL_SIZE;
        let small = Bytes::from(random_test_data(SIZE as usize));
        let path = tempdir.path().join("small.data");
        std::fs::write(&path, &small).unwrap();
        let (outboard, hash) = raw_outboard(&small);
        let (tt, size) = db
            .import_file(path, ImportMode::Copy, BlobFormat::Raw, np())
            .await
            .unwrap();
        let actual = db.entry_state(*tt.hash()).await.unwrap();
        let expected = EntryState::Complete {
            data_location: DataLocation::Inline(small),
            outboard_location: OutboardLocation::NotNeeded,
        };
        assert_eq!(size, SIZE);
        assert_eq!(tt.hash(), &hash);
        assert_eq!(actual.db, Some(expected));
        assert!(outboard.is_empty());
    }
    {
        const SIZE: u64 = MID_SIZE;
        let mid = Bytes::from(random_test_data(SIZE as usize));
        let path = tempdir.path().join("mid.data");
        std::fs::write(&path, &mid).unwrap();
        let (outboard, hash) = raw_outboard(&mid);
        let (tt, size) = db
            .import_file(path, ImportMode::Copy, BlobFormat::Raw, np())
            .await
            .unwrap();
        let actual = db.entry_state(*tt.hash()).await.unwrap();
        let expected = EntryState::Complete {
            data_location: DataLocation::Owned(SIZE),
            outboard_location: OutboardLocation::Inline(Bytes::from(outboard)),
        };
        assert_eq!(size, SIZE);
        assert_eq!(tt.hash(), &hash);
        assert_eq!(actual.db, Some(expected));
        assert_eq!(mid, std::fs::read(db.owned_data_path(&hash)).unwrap());
    }
    {
        const SIZE: u64 = LARGE_SIZE;
        let large = Bytes::from(random_test_data(SIZE as usize));
        let path = tempdir.path().join("mid.data");
        std::fs::write(&path, &large).unwrap();
        let (outboard, hash) = raw_outboard(&large);
        let (tt, size) = db
            .import_file(path, ImportMode::Copy, BlobFormat::Raw, np())
            .await
            .unwrap();
        let actual = db.entry_state(*tt.hash()).await.unwrap();
        let expected = EntryState::Complete {
            data_location: DataLocation::Owned(SIZE),
            outboard_location: OutboardLocation::Owned,
        };
        assert_eq!(size, SIZE);
        assert_eq!(tt.hash(), &hash);
        assert_eq!(actual.db, Some(expected));
        assert_eq!(large, std::fs::read(db.owned_data_path(&hash)).unwrap());
        assert_eq!(
            outboard,
            tokio::fs::read(db.owned_outboard_path(&hash))
                .await
                .unwrap()
        );
    }
}

#[tokio::test]
async fn import_file_reference_cases() {
    let np = IgnoreProgressSender::<ImportProgress>::default;
    let (tempdir, db) = create_test_db().await;
    {
        const SIZE: u64 = SMALL_SIZE;
        let small = Bytes::from(random_test_data(SIZE as usize));
        let path = tempdir.path().join("small.data");
        std::fs::write(&path, &small).unwrap();
        let (outboard, hash) = raw_outboard(&small);
        let (tt, size) = db
            .import_file(path, ImportMode::TryReference, BlobFormat::Raw, np())
            .await
            .unwrap();
        let actual = db.entry_state(*tt.hash()).await.unwrap();
        let expected = EntryState::Complete {
            data_location: DataLocation::Inline(small),
            outboard_location: OutboardLocation::NotNeeded,
        };
        assert_eq!(size, SIZE);
        assert_eq!(tt.hash(), &hash);
        assert_eq!(actual.db, Some(expected));
        assert!(outboard.is_empty());
    }
    {
        const SIZE: u64 = MID_SIZE;
        let mid = Bytes::from(random_test_data(SIZE as usize));
        let path = tempdir.path().join("mid.data");
        std::fs::write(&path, &mid).unwrap();
        let (outboard, hash) = raw_outboard(&mid);
        let (tt, size) = db
            .import_file(
                path.clone(),
                ImportMode::TryReference,
                BlobFormat::Raw,
                np(),
            )
            .await
            .unwrap();
        let actual = db.entry_state(*tt.hash()).await.unwrap();
        let expected = EntryState::Complete {
            data_location: DataLocation::External(vec![path.clone()], SIZE),
            outboard_location: OutboardLocation::Inline(Bytes::from(outboard)),
        };
        assert_eq!(size, SIZE);
        assert_eq!(tt.hash(), &hash);
        assert_eq!(actual.db, Some(expected));
        assert_eq!(mid, std::fs::read(path).unwrap());
        assert!(!db.owned_data_path(&hash).exists());
    }
}

#[tokio::test]
async fn import_file_error_cases() {
    let np = IgnoreProgressSender::<ImportProgress>::default;
    let (tempdir, db) = create_test_db().await;
    // relative path is not allowed
    {
        let path = PathBuf::from("relativepath.data");
        let cause = db
            .import_file(path, ImportMode::Copy, BlobFormat::Raw, np())
            .await
            .unwrap_err();
        assert_eq!(cause.kind(), io::ErrorKind::InvalidInput);
    }
    // file does not exist
    {
        let path = tempdir.path().join("pathdoesnotexist.data");
        let cause = db
            .import_file(path, ImportMode::Copy, BlobFormat::Raw, np())
            .await
            .unwrap_err();
        assert_eq!(cause.kind(), io::ErrorKind::InvalidInput);
    }
    // file is a directory
    {
        let path = tempdir.path().join("pathisdir.data");
        std::fs::create_dir_all(&path).unwrap();
        let cause = db
            .import_file(path, ImportMode::Copy, BlobFormat::Raw, np())
            .await
            .unwrap_err();
        assert_eq!(cause.kind(), io::ErrorKind::InvalidInput);
    }
    // // file is not readable for the store
    // #[cfg(unix)]
    // {
    //     let path = tempdir.path().join("forbidden.data");
    //     let data = random_test_data(1024);
    //     std::fs::write(&path, &data).unwrap();
    //     std::fs::set_permissions(&path, PermissionsExt::from_mode(0o0)).unwrap();
    //     let cause = db
    //         .import_file(path, ImportMode::Copy, BlobFormat::Raw, np())
    //         .await
    //         .unwrap_err();
    //     assert_eq!(cause.kind(), io::ErrorKind::PermissionDenied);
    // }
    drop(tempdir);
}

// #[cfg(unix)]
// #[tokio::test]
// async fn import_file_tempdir_readonly() {
//     let np = IgnoreProgressSender::<ImportProgress>::default;
//     let (tempdir, db) = create_test_db().await;
//     // temp dir is readonly, this is a bit mean since we mess with the internals of the store
//     {
//         let temp_dir = db.0.temp_file_name().parent().unwrap().to_owned();
//         std::fs::set_permissions(temp_dir, PermissionsExt::from_mode(0o0)).unwrap();
//         let path = tempdir.path().join("mid.data");
//         let data = random_test_data(MID_SIZE as usize);
//         std::fs::write(&path, &data).unwrap();
//         let cause = db
//             .import_file(path, ImportMode::Copy, BlobFormat::Raw, np())
//             .await
//             .unwrap_err();
//         assert_eq!(cause.kind(), io::ErrorKind::PermissionDenied);
//     }
//     drop(tempdir);
// }

// #[cfg(unix)]
// #[tokio::test]
// async fn import_file_datadir_readonly() {
//     let np = IgnoreProgressSender::<ImportProgress>::default;
//     let (tempdir, db) = create_test_db().await;
//     // temp dir is readonly, this is a bit mean since we mess with the internals of the store
//     {
//         let data_dir = db.0.path_options.data_path.to_owned();
//         std::fs::set_permissions(data_dir, PermissionsExt::from_mode(0o0)).unwrap();
//         let path = tempdir.path().join("mid.data");
//         let data = random_test_data(MID_SIZE as usize);
//         std::fs::write(&path, &data).unwrap();
//         let cause = db
//             .import_file(path, ImportMode::Copy, BlobFormat::Raw, np())
//             .await
//             .unwrap_err();
//         assert_eq!(cause.kind(), io::ErrorKind::PermissionDenied);
//     }
//     drop(tempdir);
// }

/// tests that owned wins over external in both cases
#[tokio::test]
async fn import_file_overwrite() {
    let np = IgnoreProgressSender::<ImportProgress>::default;
    let (tempdir, db) = create_test_db().await;
    // overwrite external with owned
    {
        let path = tempdir.path().join("mid.data");
        let data = random_test_data(MID_SIZE as usize);
        let (_outboard, hash) = raw_outboard(&data);
        std::fs::write(&path, &data).unwrap();
        let (tt1, size1) = db
            .import_file(path.clone(), ImportMode::Copy, BlobFormat::Raw, np())
            .await
            .unwrap();
        assert_eq!(size1, MID_SIZE);
        assert_eq!(tt1.hash(), &hash);
        let state = db.entry_state(hash).await.unwrap();
        assert_matches!(
            state.db,
            Some(EntryState::Complete {
                data_location: DataLocation::Owned(_),
                ..
            })
        );
        let (tt2, size2) = db
            .import_file(path, ImportMode::TryReference, BlobFormat::Raw, np())
            .await
            .unwrap();
        assert_eq!(size2, MID_SIZE);
        assert_eq!(tt2.hash(), &hash);
        let state = db.entry_state(hash).await.unwrap();
        assert_matches!(
            state.db,
            Some(EntryState::Complete {
                data_location: DataLocation::Owned(_),
                ..
            })
        );
    }
    {
        let path = tempdir.path().join("mid2.data");
        let data = random_test_data(MID_SIZE as usize);
        let (_outboard, hash) = raw_outboard(&data);
        std::fs::write(&path, &data).unwrap();
        let (tt1, size1) = db
            .import_file(
                path.clone(),
                ImportMode::TryReference,
                BlobFormat::Raw,
                np(),
            )
            .await
            .unwrap();
        let state = db.entry_state(hash).await.unwrap();
        assert_eq!(size1, MID_SIZE);
        assert_eq!(tt1.hash(), &hash);
        assert_matches!(
            state.db,
            Some(EntryState::Complete {
                data_location: DataLocation::External(_, _),
                ..
            })
        );
        let (tt2, size2) = db
            .import_file(path, ImportMode::Copy, BlobFormat::Raw, np())
            .await
            .unwrap();
        let state = db.entry_state(hash).await.unwrap();
        assert_eq!(size2, MID_SIZE);
        assert_eq!(tt2.hash(), &hash);
        assert_matches!(
            state.db,
            Some(EntryState::Complete {
                data_location: DataLocation::Owned(_),
                ..
            })
        );
    }
    drop(tempdir);
}

/// tests that export works in copy mode
#[tokio::test]
async fn export_copy_cases() {
    let np = || Box::new(|_: u64| io::Result::Ok(()));
    let (tempdir, db) = create_test_db().await;
    let small = Bytes::from(random_test_data(SMALL_SIZE as usize));
    let mid = Bytes::from(random_test_data(MID_SIZE as usize));
    let large = Bytes::from(random_test_data(LARGE_SIZE as usize));
    let small_tt = db
        .import_bytes(small.clone(), BlobFormat::Raw)
        .await
        .unwrap();
    let mid_tt = db.import_bytes(mid.clone(), BlobFormat::Raw).await.unwrap();
    let large_tt = db
        .import_bytes(large.clone(), BlobFormat::Raw)
        .await
        .unwrap();
    let small_path = tempdir.path().join("small.data");
    let mid_path = tempdir.path().join("mid.data");
    let large_path = tempdir.path().join("large.data");
    db.export(*small_tt.hash(), small_path.clone(), ExportMode::Copy, np())
        .await
        .unwrap();
    assert_eq!(small.to_vec(), std::fs::read(&small_path).unwrap());
    db.export(*mid_tt.hash(), mid_path.clone(), ExportMode::Copy, np())
        .await
        .unwrap();
    assert_eq!(mid.to_vec(), std::fs::read(&mid_path).unwrap());
    db.export(*large_tt.hash(), large_path.clone(), ExportMode::Copy, np())
        .await
        .unwrap();
    assert_eq!(large.to_vec(), std::fs::read(&large_path).unwrap());
    let state = db.entry_state(*small_tt.hash()).await.unwrap();
    assert_eq!(
        state.db,
        Some(EntryState::Complete {
            data_location: DataLocation::Inline(small),
            outboard_location: OutboardLocation::NotNeeded,
        })
    );
    let state = db.entry_state(*mid_tt.hash()).await.unwrap();
    assert_eq!(
        state.db,
        Some(EntryState::Complete {
            data_location: DataLocation::Owned(MID_SIZE),
            outboard_location: OutboardLocation::Inline(Bytes::from(raw_outboard(&mid).0)),
        })
    );
    let state = db.entry_state(*large_tt.hash()).await.unwrap();
    assert_eq!(
        state.db,
        Some(EntryState::Complete {
            data_location: DataLocation::Owned(LARGE_SIZE),
            outboard_location: OutboardLocation::Owned,
        })
    );
}

/// tests that export works in reference mode
#[tokio::test]
async fn export_reference_cases() {
    let np = || Box::new(|_: u64| io::Result::Ok(()));
    let (tempdir, db) = create_test_db().await;
    let small = Bytes::from(random_test_data(SMALL_SIZE as usize));
    let mid = Bytes::from(random_test_data(MID_SIZE as usize));
    let large = Bytes::from(random_test_data(LARGE_SIZE as usize));
    let small_tt = db
        .import_bytes(small.clone(), BlobFormat::Raw)
        .await
        .unwrap();
    let mid_tt = db.import_bytes(mid.clone(), BlobFormat::Raw).await.unwrap();
    let large_tt = db
        .import_bytes(large.clone(), BlobFormat::Raw)
        .await
        .unwrap();
    let small_path = tempdir.path().join("small.data");
    let mid_path = tempdir.path().join("mid.data");
    let large_path = tempdir.path().join("large.data");
    db.export(
        *small_tt.hash(),
        small_path.clone(),
        ExportMode::TryReference,
        np(),
    )
    .await
    .unwrap();
    assert_eq!(small.to_vec(), std::fs::read(&small_path).unwrap());
    db.export(
        *mid_tt.hash(),
        mid_path.clone(),
        ExportMode::TryReference,
        np(),
    )
    .await
    .unwrap();
    assert_eq!(mid.to_vec(), std::fs::read(&mid_path).unwrap());
    db.export(
        *large_tt.hash(),
        large_path.clone(),
        ExportMode::TryReference,
        np(),
    )
    .await
    .unwrap();
    assert_eq!(large.to_vec(), std::fs::read(&large_path).unwrap());
    let state = db.entry_state(*small_tt.hash()).await.unwrap();
    // small entries will never use external references
    assert_eq!(
        state.db,
        Some(EntryState::Complete {
            data_location: DataLocation::Inline(small),
            outboard_location: OutboardLocation::NotNeeded,
        })
    );
    // mid entries should now use external references
    let state = db.entry_state(*mid_tt.hash()).await.unwrap();
    assert_eq!(
        state.db,
        Some(EntryState::Complete {
            data_location: DataLocation::External(vec![mid_path], MID_SIZE),
            outboard_location: OutboardLocation::Inline(Bytes::from(raw_outboard(&mid).0)),
        })
    );
    // large entries should now use external references
    let state = db.entry_state(*large_tt.hash()).await.unwrap();
    assert_eq!(
        state.db,
        Some(EntryState::Complete {
            data_location: DataLocation::External(vec![large_path], LARGE_SIZE),
            outboard_location: OutboardLocation::Owned,
        })
    );
}

/// tests that export to a non existing directory fails
// #[cfg(unix)]
// #[tokio::test]
// async fn export_nonexistent_dir() {
//     let (tempdir, db) = create_test_db().await;
//     let small = Bytes::from(random_test_data(SMALL_SIZE as usize));
//     let target_dir = tempdir.path().join("export");
//     let small_tt = db
//         .import_bytes(small.clone(), BlobFormat::Raw)
//         .await
//         .unwrap();
//     let small_path = target_dir.join("small.data");
//     let cause = db
//         .export(
//             *small_tt.hash(),
//             small_path.clone(),
//             ExportMode::Copy,
//             Box::new(|_: u64| io::Result::Ok(())),
//         )
//         .await
//         .unwrap_err();
//     assert_eq!(cause.kind(), io::ErrorKind::PermissionDenied);
// }

#[tokio::test]
async fn entry_drop() {
    let _ = tracing_subscriber::fmt::try_init();
    let testdir = tempfile::tempdir().unwrap();
    let db_path = testdir.path().join("test.redb");
    let options = Options {
        path: PathOptions::new(testdir.path()),
        inline: Default::default(),
    };
    let db = Store::new(db_path, options).await.unwrap();
    let data = random_test_data(1024 * 1024);
    let (_outboard, hash) = raw_outboard(data.as_slice());
    let entry = db.get_or_create(hash, 0).await.unwrap();
    let id = entry.0.id;
    let e2 = entry.clone();
    assert_eq!(id, e2.0.id);
    drop(entry);
    drop(e2);
    db.sync().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let entry = db.get_or_create(hash, 0).await.unwrap();
    assert_ne!(id, entry.0.id);
    drop(db);
}

#[tokio::test]
async fn actor_store_smoke() {
    let testdir = tempfile::tempdir().unwrap();
    let db_path = testdir.path().join("test.redb");
    let options = Options {
        path: PathOptions::new(testdir.path()),
        inline: Default::default(),
    };
    let db = Store::new(db_path, options).await.unwrap();
    db.dump().await.unwrap();
    let data = random_test_data(1024 * 1024);
    #[allow(clippy::single_range_in_vec_init)]
    let ranges = [0..data.len() as u64];
    let (hash, chunk_ranges, wire_data) = make_wire_data(&data, &ranges);
    let handle = db.get_or_create(hash, 0).await.unwrap();
    decode_response_into_batch(
        hash,
        IROH_BLOCK_SIZE,
        chunk_ranges.clone(),
        Cursor::new(wire_data),
        handle.batch_writer().await.unwrap(),
    )
    .await
    .unwrap();
    validate(&handle.0, &data, &ranges).await;
    db.insert_complete(handle).await.unwrap();
    db.sync().await.unwrap();
    db.dump().await.unwrap();
}
