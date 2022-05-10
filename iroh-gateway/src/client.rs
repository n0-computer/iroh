// this is just a stub for future integration with iroh-gateway

use crate::metrics::*;
use crate::response::ResponseFormat;
use axum::body::Body;
use metrics::{counter, gauge, histogram, increment_counter};
use rand::{prelude::StdRng, Rng, SeedableRng};
use std::{fs::File, io::Read, path::Path, time::Duration};

#[derive(Debug, Clone, Copy)]
pub struct Client {}

pub const CHUNK_SIZE: usize = 1024;

impl Client {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn get_file_simulated(
        &self,
        _path: &str,
        start_time: std::time::Instant,
    ) -> Result<Body, String> {
        let (mut sender, body) = Body::channel();
        let mut rng: StdRng = SeedableRng::from_entropy();

        // some random latency
        tokio::time::sleep(Duration::from_millis(rng.gen_range(0..150))).await;

        tokio::spawn(async move {
            let test_path = Path::new("test_files/test_big.txt");
            let mut file = File::open(test_path).unwrap();
            let mut buf = [0u8; CHUNK_SIZE];
            let mut first_block = true;
            if rng.gen_range(0..250) < 200 {
                // simulate a cache miss
                increment_counter!(METRICS_CACHE_MISS);
            } else {
                // simulate a cache hit
                increment_counter!(METRICS_CACHE_HIT);
            }

            let mut f_size: f64 = 0.0;

            while let Ok(n) = file.read(&mut buf) {
                if first_block {
                    gauge!(METRICS_TIME_TO_FETCH_FIRST_BLOCK, start_time.elapsed());
                    histogram!(METRICS_HIST_TTFB, start_time.elapsed());
                }
                counter!(METRICS_BYTES_FETCHED, n as u64);
                f_size += n as f64;
                gauge!(
                    METRICS_BITRATE_IN,
                    f_size / start_time.elapsed().as_secs_f64()
                );
                if n == 0 {
                    gauge!(METRICS_TIME_TO_FETCH_FULL_FILE, start_time.elapsed());
                    gauge!(METRICS_TIME_TO_SERVE_FULL_FILE, start_time.elapsed());
                    histogram!(METRICS_HIST_TTSERVE, start_time.elapsed());
                    break;
                }
                sender
                    .send_data(axum::body::Bytes::from(buf[..n].to_vec()))
                    .await
                    .unwrap();
                // todo(arqu): handle sender error
                if first_block {
                    first_block = false;
                    gauge!(METRICS_TIME_TO_SERVE_FIRST_BLOCK, start_time.elapsed());
                }
                gauge!(
                    METRICS_BITRATE_OUT,
                    f_size / start_time.elapsed().as_secs_f64()
                );
                counter!(METRICS_BYTES_STREAMED, n as u64);
                tokio::time::sleep(Duration::from_millis(rng.gen_range(0..150))).await;
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
