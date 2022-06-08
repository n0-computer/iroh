use std::{
    cell::RefCell,
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use anyhow::Result;
use config::{Environment, File, Map, Source, Value, ValueKind};
use dirs::home_dir;

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

/// Path that leads to a file in the iroh home directory
pub fn iroh_home_path(file_name: &str) -> Option<PathBuf> {
    let home = home_dir()?;
    Some(Path::new(&home).join(IROH_DIR).join(file_name))
}

/// insert a value into a `config::Map`
pub fn insert_into_config_map<I: Into<String>, V: Into<ValueKind>>(
    map: &mut Map<String, Value>,
    field: I,
    val: V,
) {
    map.insert(field.into(), Value::new(None, val));
}

/// make a config using a default, file sources, environment variables, and commandline flag
/// overrides
pub fn make_config<T, S, V>(
    default: T,
    file_paths: Vec<Option<PathBuf>>,
    env_prefex: &str,
    flag_overrides: HashMap<S, V>,
) -> Result<T>
where
    T: serde::de::DeserializeOwned + Source + Send + Sync + 'static,
    S: AsRef<str>,
    V: Into<Value>,
{
    // create config builder and add default as first source
    let mut builder = config::Config::builder().add_source(default);

    // layer on config options from files
    for path in file_paths.into_iter().flatten() {
        if path.exists() {
            let p = path.to_str().ok_or_else(|| anyhow::anyhow!("empty path"))?;
            builder = builder.add_source(File::with_name(p));
        }
    }

    // next, add any environment variables
    builder = builder.add_source(
        Environment::with_prefix(env_prefex)
            .try_parsing(true)
            .separator("_")
            .list_separator(","),
    );

    // finally, override any values
    for (flag, val) in flag_overrides.into_iter() {
        builder = builder.set_override(flag, val)?;
    }

    let config: T = builder.build()?.try_deserialize()?;
    Ok(config)
}
