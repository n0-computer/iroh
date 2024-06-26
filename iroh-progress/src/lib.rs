use anyhow::{bail, Result};
use console::style;
use futures_lite::{Stream, StreamExt};
use indicatif::{
    HumanBytes, HumanDuration, MultiProgress, ProgressBar, ProgressDrawTarget, ProgressState,
    ProgressStyle,
};
use iroh_blobs::{
    get::{db::DownloadProgress, progress::BlobProgress, Stats},
    Hash,
};

pub async fn show_download_progress(
    hash: Hash,
    mut stream: impl Stream<Item = Result<DownloadProgress>> + Unpin,
) -> Result<()> {
    eprintln!("Fetching: {}", hash);
    let mp = MultiProgress::new();
    mp.set_draw_target(ProgressDrawTarget::stderr());
    let op = mp.add(make_overall_progress());
    let ip = mp.add(make_individual_progress());
    op.set_message(format!("{} Connecting ...\n", style("[1/3]").bold().dim()));
    let mut seq = false;
    while let Some(x) = stream.next().await {
        match x? {
            DownloadProgress::InitialState(state) => {
                if state.connected {
                    op.set_message(format!("{} Requesting ...\n", style("[2/3]").bold().dim()));
                }
                if let Some(count) = state.root.child_count {
                    op.set_message(format!(
                        "{} Downloading {} blob(s)\n",
                        style("[3/3]").bold().dim(),
                        count + 1,
                    ));
                    op.set_length(count + 1);
                    op.reset();
                    op.set_position(state.current.map(u64::from).unwrap_or(0));
                    seq = true;
                }
                if let Some(blob) = state.get_current() {
                    if let Some(size) = blob.size {
                        ip.set_length(size.value());
                        ip.reset();
                        match blob.progress {
                            BlobProgress::Pending => {}
                            BlobProgress::Progressing(offset) => ip.set_position(offset),
                            BlobProgress::Done => ip.finish_and_clear(),
                        }
                        if !seq {
                            op.finish_and_clear();
                        }
                    }
                }
            }
            DownloadProgress::FoundLocal { .. } => {}
            DownloadProgress::Connected => {
                op.set_message(format!("{} Requesting ...\n", style("[2/3]").bold().dim()));
            }
            DownloadProgress::FoundHashSeq { children, .. } => {
                op.set_message(format!(
                    "{} Downloading {} blob(s)\n",
                    style("[3/3]").bold().dim(),
                    children + 1,
                ));
                op.set_length(children + 1);
                op.reset();
                seq = true;
            }
            DownloadProgress::Found { size, child, .. } => {
                if seq {
                    op.set_position(child.into());
                } else {
                    op.finish_and_clear();
                }
                ip.set_length(size);
                ip.reset();
            }
            DownloadProgress::Progress { offset, .. } => {
                ip.set_position(offset);
            }
            DownloadProgress::Done { .. } => {
                ip.finish_and_clear();
            }
            DownloadProgress::AllDone(Stats {
                bytes_read,
                elapsed,
                ..
            }) => {
                op.finish_and_clear();
                eprintln!(
                    "Transferred {} in {}, {}/s",
                    HumanBytes(bytes_read),
                    HumanDuration(elapsed),
                    HumanBytes((bytes_read as f64 / elapsed.as_secs_f64()) as u64)
                );
                break;
            }
            DownloadProgress::Abort(e) => {
                bail!("download aborted: {}", e);
            }
        }
    }
    Ok(())
}
fn make_overall_progress() -> ProgressBar {
    let pb = ProgressBar::hidden();
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    pb.set_style(
        ProgressStyle::with_template(
            "{msg}{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len}",
        )
        .unwrap()
        .progress_chars("#>-"),
    );
    pb
}

fn make_individual_progress() -> ProgressBar {
    let pb = ProgressBar::hidden();
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    pb.set_style(
        ProgressStyle::with_template("{msg}{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .with_key(
                "eta",
                |state: &ProgressState, w: &mut dyn std::fmt::Write| {
                    write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()
                },
            )
            .progress_chars("#>-"),
    );
    pb
}
