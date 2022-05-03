use futures::TryStreamExt;
use iroh_car::*;
use tokio::fs::{self, File};
use tokio::io::BufReader;

#[tokio::test]
async fn roundtrip_carv1_test_file() {
    let file = File::open("tests/testv1.car").await.unwrap();
    let buf_reader = BufReader::new(file);

    let car_reader = CarReader::new(buf_reader).await.unwrap();
    let header = car_reader.header().clone();
    let files: Vec<_> = car_reader.stream().try_collect().await.unwrap();
    assert_eq!(files.len(), 35);

    let mut buffer = Vec::new();
    let mut writer = CarWriter::new(header, &mut buffer);
    for (cid, data) in &files {
        writer.write(*cid, data).await.unwrap();
    }
    writer.finish().await.unwrap();

    let file = fs::read("tests/testv1.car").await.unwrap();
    assert_eq!(file, buffer);
}

#[tokio::test]
async fn roundtrip_carv1_basic_fixtures_file() {
    let file = File::open("tests/carv1_basic.car").await.unwrap();
    let buf_reader = BufReader::new(file);

    let car_reader = CarReader::new(buf_reader).await.unwrap();
    let header = car_reader.header().clone();

    assert_eq!(
        car_reader.header().roots(),
        [
            "bafyreihyrpefhacm6kkp4ql6j6udakdit7g3dmkzfriqfykhjw6cad5lrm"
                .parse()
                .unwrap(),
            "bafyreidj5idub6mapiupjwjsyyxhyhedxycv4vihfsicm2vt46o7morwlm"
                .parse()
                .unwrap()
        ]
    );

    let files: Vec<_> = car_reader.stream().try_collect().await.unwrap();
    assert_eq!(files.len(), 8);

    let cids = [
        "bafyreihyrpefhacm6kkp4ql6j6udakdit7g3dmkzfriqfykhjw6cad5lrm",
        "QmNX6Tffavsya4xgBi2VJQnSuqy9GsxongxZZ9uZBqp16d",
        "bafkreifw7plhl6mofk6sfvhnfh64qmkq73oeqwl6sloru6rehaoujituke",
        "QmWXZxVQ9yZfhQxLD35eDR8LiMRsYtHxYqTFCBbJoiJVys",
        "bafkreiebzrnroamgos2adnbpgw5apo3z4iishhbdx77gldnbk57d4zdio4",
        "QmdwjhxpxzcMsR3qUuj7vUL8pbA7MgR3GAxWi2GLHjsKCT",
        "bafkreidbxzk2ryxwwtqxem4l3xyyjvw35yu4tcct4cqeqxwo47zhxgxqwq",
        "bafyreidj5idub6mapiupjwjsyyxhyhedxycv4vihfsicm2vt46o7morwlm",
    ];

    for (expected_cid, (cid, _)) in cids.iter().zip(&files) {
        assert_eq!(*cid, expected_cid.parse().unwrap());
    }

    let mut buffer = Vec::new();
    let mut writer = CarWriter::new(header, &mut buffer);
    for (cid, data) in &files {
        writer.write(*cid, data).await.unwrap();
    }
    writer.finish().await.unwrap();

    let file = fs::read("tests/carv1_basic.car").await.unwrap();
    assert_eq!(file, buffer);
}
