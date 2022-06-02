use std::{
    cell::RefCell,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use anyhow::Result;
use dirs::home_dir;
use serde::de::DeserializeOwned;

const IROH_DIR: &str = "./iroh";

/// Blocks current thread until ctrl-c is received
pub async fn block_until_sigint() {
    let (ctrlc_send, ctrlc_oneshot) = futures::channel::oneshot::channel();
    let ctrlc_send_c = RefCell::new(Some(ctrlc_send));

    let running = Arc::new(AtomicUsize::new(0));
    ctrlc::set_handler(move || {
        let prev = running.fetch_add(1, Ordering::SeqCst);
        if prev == 0 {
            println!("Got interrupt, shutting down...");
            // Send sig int in channel to blocking task
            if let Some(ctrlc_send) = ctrlc_send_c.try_borrow_mut().unwrap().take() {
                ctrlc_send.send(()).expect("Error sending ctrl-c message");
            }
        } else {
            std::process::exit(0);
        }
    })
    .expect("Error setting Ctrl-C handler");

    ctrlc_oneshot.await.unwrap();
}

/// Given a list of Option<paths>, loads a config for the first existing path
pub fn from_toml_file<D: DeserializeOwned>(paths: Vec<Option<PathBuf>>) -> Option<Result<D>> {
    if let Some(path) = paths.into_iter().filter(|x| x.is_some()).flatten().next() {
        let mut config_file = match File::open(path.as_path()) {
            Ok(f) => f,
            Err(e) => return Some(Err(e.into())),
        };
        let mut config_bytes: Vec<u8> = Vec::new();
        match config_file.read_to_end(&mut config_bytes) {
            Ok(_) => {}
            Err(e) => return Some(Err(e.into())),
        };
        let config: D = match toml::from_slice(&config_bytes) {
            Ok(c) => c,
            Err(e) => return Some(Err(e.into())),
        };
        return Some(Ok(config));
    }
    None
}

/// Path that leads to a file in the iroh home directory
pub fn iroh_home_path(file_name: &str) -> Option<PathBuf> {
    let home = home_dir()?;
    Some(Path::new(&home).join(IROH_DIR).join(file_name))
}
