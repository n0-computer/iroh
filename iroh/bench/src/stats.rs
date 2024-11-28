use std::time::Duration;

use hdrhistogram::Histogram;

#[derive(Default, Debug)]
pub struct Stats {
    pub total_size: u64,
    pub total_duration: Duration,
    pub streams: usize,
    pub stream_stats: StreamStats,
}

impl Stats {
    pub fn stream_finished(&mut self, stream_result: TransferResult) {
        self.total_size += stream_result.size;
        self.streams += 1;

        self.stream_stats
            .duration_hist
            .record(stream_result.duration.as_millis() as u64)
            .unwrap();
        self.stream_stats
            .throughput_hist
            .record(stream_result.throughput as u64)
            .unwrap();
        self.stream_stats
            .ttfb_hist
            .record(stream_result.ttfb.as_nanos() as u64)
            .unwrap();
        self.stream_stats
            .chunk_time
            .record(
                stream_result.duration.as_nanos() as u64 / std::cmp::max(stream_result.chunks, 1),
            )
            .unwrap();
        self.stream_stats.chunks += stream_result.chunks;
        self.stream_stats
            .chunk_size
            .record(stream_result.avg_chunk_size)
            .unwrap();
    }

    pub fn print(&self, stat_name: &str) {
        println!("Overall {stat_name} stats:\n");
        println!(
            "Transferred {} bytes on {} streams in {:4.2?} ({:.2} MiB/s)\n",
            self.total_size,
            self.streams,
            self.total_duration,
            throughput_bps(self.total_duration, self.total_size) / 1024.0 / 1024.0
        );

        let avg_ttfb = self.stream_stats.ttfb_hist.mean() / 1_000.0;
        println!("Time to first byte (TTFB): {avg_ttfb}ms\n");

        let chunks = self.stream_stats.chunks;
        println!("Total chunks: {chunks}\n");
        let avg_chunk_time = self.stream_stats.chunk_time.mean() / 1_000.0;
        println!("Average chunk time: {avg_chunk_time}ms\n");
        let avg_chunk_size = self.stream_stats.chunk_size.mean() / 1024.0;
        println!("Average chunk size: {avg_chunk_size:.2}KiB\n");

        println!("Stream {stat_name} metrics:\n");

        println!("      │  Throughput   │ Duration ");
        println!("──────┼───────────────┼──────────");

        let print_metric = |label: &'static str, get_metric: fn(&Histogram<u64>) -> u64| {
            println!(
                " {} │ {:7.2} MiB/s │ {:>9.2?}",
                label,
                get_metric(&self.stream_stats.throughput_hist) as f64 / 1024.0 / 1024.0,
                Duration::from_millis(get_metric(&self.stream_stats.duration_hist))
            );
        };

        print_metric("AVG ", |hist| hist.mean() as u64);
        print_metric("P0  ", |hist| hist.value_at_quantile(0.00));
        print_metric("P10 ", |hist| hist.value_at_quantile(0.10));
        print_metric("P50 ", |hist| hist.value_at_quantile(0.50));
        print_metric("P90 ", |hist| hist.value_at_quantile(0.90));
        print_metric("P100", |hist| hist.value_at_quantile(1.00));
    }
}

#[derive(Debug)]
pub struct StreamStats {
    pub duration_hist: Histogram<u64>,
    pub throughput_hist: Histogram<u64>,
    pub ttfb_hist: Histogram<u64>,
    pub chunk_time: Histogram<u64>,
    pub chunks: u64,
    pub chunk_size: Histogram<u64>,
}

impl Default for StreamStats {
    fn default() -> Self {
        Self {
            duration_hist: Histogram::<u64>::new(3).unwrap(),
            throughput_hist: Histogram::<u64>::new(3).unwrap(),
            ttfb_hist: Histogram::<u64>::new(3).unwrap(),
            chunk_time: Histogram::<u64>::new(3).unwrap(),
            chunks: 0,
            chunk_size: Histogram::<u64>::new(3).unwrap(),
        }
    }
}

#[derive(Debug)]
pub struct TransferResult {
    pub duration: Duration,
    pub size: u64,
    pub throughput: f64,
    pub ttfb: Duration,
    pub chunks: u64,
    pub avg_chunk_size: u64,
}

impl TransferResult {
    pub fn new(duration: Duration, size: u64, ttfb: Duration, chunks: u64) -> Self {
        let throughput = throughput_bps(duration, size);
        TransferResult {
            duration,
            size,
            throughput,
            ttfb,
            chunks,
            avg_chunk_size: size / std::cmp::max(chunks, 1),
        }
    }
}

pub fn throughput_bps(duration: Duration, size: u64) -> f64 {
    (size as f64) / (duration.as_secs_f64())
}
