use std::{
    fs::OpenOptions,
    io::{self, Write},
    path::Path,
};

/// overwrite a file with the given data.
///
/// This is almost like `std::fs::write`, but it does not truncate the file.
///
/// So if you overwrite a file with less data than it had before, the file will
/// still have the same size as before.
///
/// Also, if you overwrite a file with the same data as it had before, the
/// file will be unchanged even if the overwrite operation is interrupted.
pub fn overwrite_and_sync(path: &Path, data: &[u8]) -> io::Result<std::fs::File> {
    tracing::trace!(
        "overwriting file {} with {} bytes",
        path.display(),
        data.len()
    );
    // std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    // tracing::error!("{}", path.parent().unwrap().display());
    // tracing::error!("{}", path.parent().unwrap().metadata().unwrap().is_dir());
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    file.write_all(data)?;
    // todo: figure out if it is safe to not sync here
    file.sync_all()?;
    Ok(file)
}

/// Read a file into memory and then delete it.
pub fn read_and_remove(path: &Path) -> io::Result<Vec<u8>> {
    let data = std::fs::read(path)?;
    // todo: should we fail here or just log a warning?
    // remove could fail e.g. on windows if the file is still open
    std::fs::remove_file(path)?;
    Ok(data)
}

/// A wrapper for a flume receiver that allows peeking at the next message.
#[derive(Debug)]
pub(super) struct PeekableFlumeReceiver<T> {
    msg: Option<T>,
    recv: async_channel::Receiver<T>,
}

#[allow(dead_code)]
impl<T> PeekableFlumeReceiver<T> {
    pub fn new(recv: async_channel::Receiver<T>) -> Self {
        Self { msg: None, recv }
    }

    /// Receive the next message.
    ///
    /// Will block if there are no messages.
    /// Returns None only if there are no more messages (sender is dropped).
    pub async fn recv(&mut self) -> Option<T> {
        if let Some(msg) = self.msg.take() {
            return Some(msg);
        }
        self.recv.recv().await.ok()
    }

    /// Push back a message. This will only work if there is room for it.
    /// Otherwise, it will fail and return the message.
    pub fn push_back(&mut self, msg: T) -> std::result::Result<(), T> {
        if self.msg.is_none() {
            self.msg = Some(msg);
            Ok(())
        } else {
            Err(msg)
        }
    }
}
