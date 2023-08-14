use std::{collections::HashMap, time::Duration};

use anyhow::Result;
use console::{style, Emoji};
use futures::StreamExt;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use iroh::{client::quic::RpcClient, rpc_protocol::ValidateRequest};
use iroh_bytes::{baomap::ValidateProgress, Hash};

pub async fn run(client: RpcClient, repair: bool) -> Result<()> {
    let mut state = ValidateProgressState::new();
    let mut response = client.server_streaming(ValidateRequest { repair }).await?;

    while let Some(item) = response.next().await {
        match item? {
            ValidateProgress::Starting { total } => {
                state.starting(total);
            }
            ValidateProgress::Entry {
                id,
                hash,
                path,
                size,
            } => {
                state.add_entry(id, hash, path, size);
            }
            ValidateProgress::Progress { id, offset } => {
                state.progress(id, offset);
            }
            ValidateProgress::Done { id, error } => {
                state.done(id, error);
            }
            ValidateProgress::Abort(error) => {
                state.abort(error.to_string());
                break;
            }
            ValidateProgress::AllDone => {
                break;
            }
        }
    }
    Ok(())
}

struct ValidateProgressState {
    mp: MultiProgress,
    pbs: HashMap<u64, ProgressBar>,
    overall: ProgressBar,
    total: u64,
    errors: u64,
    successes: u64,
}

impl ValidateProgressState {
    fn new() -> Self {
        let mp = MultiProgress::new();
        let overall = mp.add(ProgressBar::new(0));
        overall.enable_steady_tick(Duration::from_millis(500));
        Self {
            mp,
            pbs: HashMap::new(),
            overall,
            total: 0,
            errors: 0,
            successes: 0,
        }
    }

    fn starting(&mut self, total: u64) {
        self.total = total;
        self.errors = 0;
        self.successes = 0;
        self.overall.set_position(0);
        self.overall.set_length(total);
        self.overall.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:60.cyan/blue}] {msg}")
                .unwrap()
                .progress_chars("=>-"),
        );
    }

    fn add_entry(&mut self, id: u64, hash: Hash, path: Option<String>, size: u64) {
        let pb = self.mp.insert_before(&self.overall, ProgressBar::new(size));
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {msg} {bytes}/{total_bytes} ({bytes_per_sec}, eta {eta})").unwrap()
            .progress_chars("=>-"));
        let msg = if let Some(path) = path {
            path
        } else {
            format!("outboard {}", hash)
        };
        pb.set_message(msg);
        pb.set_position(0);
        pb.set_length(size);
        pb.enable_steady_tick(Duration::from_millis(500));
        self.pbs.insert(id, pb);
    }

    fn progress(&mut self, id: u64, progress: u64) {
        if let Some(pb) = self.pbs.get_mut(&id) {
            pb.set_position(progress);
        }
    }

    fn abort(self, error: String) {
        let error_line = self.mp.add(ProgressBar::new(0));
        error_line.set_style(ProgressStyle::default_bar().template("{msg}").unwrap());
        error_line.set_message(error);
    }

    fn done(&mut self, id: u64, error: Option<String>) {
        if let Some(pb) = self.pbs.remove(&id) {
            let ok_char = style(Emoji("✔", "OK")).green();
            let fail_char = style(Emoji("✗", "Error")).red();
            let ok = error.is_none();
            let msg = match error {
                Some(error) => format!("{} {} {}", pb.message(), fail_char, error),
                None => format!("{} {}", pb.message(), ok_char),
            };
            if ok {
                self.successes += 1;
            } else {
                self.errors += 1;
            }
            self.overall.set_position(self.errors + self.successes);
            self.overall.set_message(format!(
                "Overall {} {}, {} {}",
                self.errors, fail_char, self.successes, ok_char
            ));
            if ok {
                pb.finish_and_clear();
            } else {
                pb.set_style(ProgressStyle::default_bar().template("{msg}").unwrap());
                pb.finish_with_message(msg);
            }
        }
    }
}
