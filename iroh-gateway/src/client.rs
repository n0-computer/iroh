// this is just a stub for future integration with iroh-gateway

use crate::response::ResponseFormat;
use axum::body::Body;
use rand::{prelude::StdRng, Rng, SeedableRng};
use std::{fs::File, io::Read, path::Path, time::Duration};

#[derive(Debug, Clone, Copy)]
pub struct Client {}

pub const CHUNK_SIZE: usize = 256;

impl Client {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn get_file_simulated(&self, _path: &str) -> Result<Body, String> {
        let (mut sender, body) = Body::channel();
        // let mut rng = rand::thread_rng();
        let mut rng: StdRng = SeedableRng::from_entropy();

        tokio::spawn(async move {
            let test_path = Path::new("test_files/test_big.txt");
            let mut file = File::open(test_path).unwrap();
            let mut buf = [0u8; CHUNK_SIZE];

            loop {
                let n = match file.read(&mut buf) {
                    Ok(n) => n,
                    Err(_) => break,
                };
                if n == 0 {
                    break;
                }
                sender
                    .send_data(axum::body::Bytes::from(buf[..n].to_vec()))
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_millis(rng.gen_range(0..500))).await;
            }
        });

        Ok(body)
    }
}

#[derive(Debug, Clone)]
pub struct Request {
    pub format: ResponseFormat,
    pub cid: String,
    pub full_content_path: String,
    pub query_file_name: String,
    pub content_path: String,
    pub download: bool,
}
