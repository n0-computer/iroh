use std::time::Duration;

use hdrhistogram::Histogram;

#[derive(Default)]
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

pub struct StreamStats {
    pub duration_hist: Histogram<u64>,
    pub throughput_hist: Histogram<u64>,
}

impl Default for StreamStats {
    fn default() -> Self {
        Self {
            duration_hist: Histogram::<u64>::new(3).unwrap(),
            throughput_hist: Histogram::<u64>::new(3).unwrap(),
        }
    }
}

#[derive(Debug)]
pub struct TransferResult {
    pub duration: Duration,
    pub size: u64,
    pub throughput: f64,
}

impl TransferResult {
    pub fn new(duration: Duration, size: u64) -> Self {
        let throughput = throughput_bps(duration, size);
        TransferResult {
            duration,
            size,
            throughput,
        }
    }
}

pub fn throughput_bps(duration: Duration, size: u64) -> f64 {
    (size as f64) / (duration.as_secs_f64())
}
