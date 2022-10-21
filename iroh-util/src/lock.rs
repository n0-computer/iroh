use anyhow::{anyhow, Result as AnyhowResult};
use std::fs::File;
use std::io::prelude::*;
use std::io::ErrorKind;
use std::io::Write;
use std::path::PathBuf;
use sysinfo::{Pid, ProcessExt, ProcessStatus, System, SystemExt};
use thiserror::Error;
use tracing::log::warn;

pub fn acquire_or_exit(lock: &mut ProgramLock, daemon_name: &str) -> Result<(), LockError> {
    if lock.is_locked()? {
        eprintln!("{} is already running, stopping.", daemon_name);
        std::process::exit(crate::exitcodes::LOCKED);
    }
    lock.acquire()
}

/// Manages a lock file used to track if an iroh program
/// is already running.
/// An acquired lock is released either when the object is dropped
/// or when the program stops, which removes the file from disk
pub struct ProgramLock {
    path: PathBuf,
    lock: Option<sysinfo::Pid>,
}

impl ProgramLock {
    /// Create a new lock for the given program. This does not yet acquire the lock.
    pub fn new(prog_name: &str) -> Result<Self, LockError> {
        let path = crate::iroh_data_path(&format!("{}.lock", prog_name))
            .map_err(|e| LockError::InvalidPath { source: e })?;
        Ok(Self { path, lock: None })
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Check if the current program is locked or not.
    pub fn is_locked(&self) -> Result<bool, LockError> {
        if !self.path.exists() {
            return Ok(false);
        }

        // path exists, examine lock PID
        let pid = read_lock(&self.path)?;
        process_is_running(pid).map_err(|e| LockError::Uncategorized { source: e })
    }

    /// returns
    pub fn active_pid(&self) -> Result<Pid, LockError> {
        if !self.path.exists() {
            return Err(LockError::NoLock(self.path.clone()));
        }

        // path exists, examine lock PID
        let pid = read_lock(&self.path)?;
        let running =
            process_is_running(pid).map_err(|e| LockError::Uncategorized { source: e })?;
        if running {
            Ok(pid)
        } else {
            Err(LockError::ZombieLock(self.path.clone()))
        }
    }

    /// Try to acquire a lock for this program.
    pub fn acquire(&mut self) -> Result<(), LockError> {
        match self.is_locked() {
            Ok(false) => self
                .write()
                .map_err(|e| LockError::Uncategorized { source: anyhow!(e) }),
            Ok(true) => Err(LockError::Locked(self.path.clone())),
            Err(e) => match e {
                LockError::CorruptLock(_) => {
                    // overwrite corrupt locks
                    self.write().map_err(|e| LockError::Uncategorized {
                        source: anyhow!("{}", e),
                    })
                }
                e => Err(LockError::Uncategorized {
                    source: anyhow!("{}", e),
                }),
            },
        }
    }

    fn write(&mut self) -> AnyhowResult<()> {
        // create lock. ensure path to lock exists
        std::fs::create_dir_all(&crate::iroh_data_root()?)?;
        let mut file = File::create(&self.path)?;
        let pid = sysinfo::get_current_pid().unwrap();
        file.write_all(pid.to_string().as_bytes())?;
        self.lock = Some(pid);
        Ok(())
    }
}

impl Drop for ProgramLock {
    fn drop(&mut self) {
        if self.lock.is_some() {
            if let Err(err) = std::fs::remove_file(&self.path) {
                warn!("removing lock: {}", err);
            }
        }
    }
}

fn process_is_running(pid: Pid) -> AnyhowResult<bool> {
    let this_pid = sysinfo::get_current_pid().unwrap();
    if pid == this_pid {
        return Ok(true);
    }

    // TODO(b5) - docs say we shouldn't be allocating on each call like this:
    // https://docs.rs/sysinfo/0.26.5/sysinfo/index.html#usage
    // I'm suspicious this pattern might be alright. Seems the underlying lib
    // doesn't do much hydrating, but System may be a large memory allocation
    let mut s = System::new();
    if !s.refresh_process(pid) {
        return Ok(false);
    }

    match s.process(pid) {
        Some(process) => {
            match process.status() {
                // see https://docs.rs/sysinfo/0.26.5/sysinfo/enum.ProcessStatus.html for details
                ProcessStatus::Idle => Ok(true),
                ProcessStatus::Run => Ok(true),
                ProcessStatus::Sleep => Ok(true),
                ProcessStatus::Waking => Ok(true),

                ProcessStatus::Stop => Ok(false),
                ProcessStatus::Zombie => Ok(false),
                ProcessStatus::Tracing => Ok(false),
                ProcessStatus::Dead => Ok(false),
                ProcessStatus::Wakekill => Ok(false),
                ProcessStatus::Parked => Ok(false),
                ProcessStatus::LockBlocked => Ok(false),
                ProcessStatus::Unknown(_s) => Ok(false),
            }
        }
        None => Err(anyhow!("couldn't find system process with id {}", pid)),
    }
}

/// Report Process ID stored in a lock file
pub fn read_lock_pid(prog_name: &str) -> Result<Pid, LockError> {
    let path = crate::iroh_data_path(&format!("{}.lock", prog_name))
        .map_err(|e| LockError::Uncategorized { source: e })?;
    read_lock(&path)
}

fn read_lock(path: &PathBuf) -> Result<Pid, LockError> {
    let mut file = File::open(&path).map_err(|e| match e.kind() {
        ErrorKind::NotFound => LockError::NoLock(path.clone()),
        e => LockError::Uncategorized {
            source: anyhow!("{}", e),
        },
    })?;
    let mut pid = String::new();
    file.read_to_string(&mut pid)
        .map_err(|_| LockError::CorruptLock(path.clone()))?;
    let pid = pid
        .parse::<i32>()
        .map_err(|_| LockError::CorruptLock(path.clone()))?;
    Ok(Pid::from(pid))
}

/// LockError classifies non-generic errors related to program locks
#[derive(Error, Debug)]
pub enum LockError {
    // lock present when one is not expected
    #[error("Locked")]
    Locked(PathBuf),
    #[error("No lock file at {0}")]
    NoLock(PathBuf),
    /// Failure to parse contents of lock file
    #[error("Corrupt lock file contents at {0}")]
    CorruptLock(PathBuf),
    #[error("Cannot detrmine status of process holding this lock")]
    ZombieLock(PathBuf),
    // location for lock no bueno
    #[error("invalid path for lock file: {source}")]
    InvalidPath {
        #[source]
        source: anyhow::Error,
    },
    /// catchall error type
    #[error("{source}")]
    Uncategorized {
        #[from]
        source: anyhow::Error,
    },
}

#[cfg(all(test, unix))]
mod test {
    use super::*;

    fn create_test_lock(name: &str) -> ProgramLock {
        ProgramLock {
            path: PathBuf::from(name),
            lock: None,
        }
    }

    #[test]
    fn test_corrupt_lock() {
        let path = PathBuf::from("lock.lock");
        let mut f = File::create(&path).unwrap();
        write!(f, "oh noes, not a lock file").unwrap();
        let e = read_lock(&path).err().unwrap();
        match e {
            LockError::CorruptLock(_) => (),
            _e => {
                panic!("expected CorruptLock")
            }
        }
    }

    #[test]
    fn test_locks() {
        use nix::unistd::{fork, ForkResult::*};
        use std::io::{Read, Write};
        use std::time::Duration;

        // Start with no lock file.
        let _ = std::fs::remove_file("test1.lock");

        let mut lock = create_test_lock("test1.lock");
        assert!(!lock.is_locked().unwrap());
        assert!(read_lock(&PathBuf::from("test1.lock")).is_err());

        lock.acquire().unwrap();

        assert!(lock.is_locked().unwrap());
        // ensure call to is_locked doesn't affect PID reporting
        assert_eq!(
            sysinfo::get_current_pid().unwrap(),
            read_lock(&PathBuf::from("test1.lock")).unwrap()
        );

        // Spawn a child process to check we can't get the same lock.
        // assert!() failures in the child are not reported by the test
        // harness, so we write the result in a file from the child and
        // read them back in the parent after a reasonable delay :(
        unsafe {
            match fork() {
                Ok(Parent { child: _ }) => {
                    let _ = std::fs::remove_file("lock_test.result");

                    std::thread::sleep(Duration::from_secs(1));

                    let mut result = std::fs::File::open("lock_test.result").unwrap();
                    let mut buf = String::new();
                    let _ = result.read_to_string(&mut buf);
                    assert_eq!(
                        buf,
                        format!(
                            "locked1=true, locked2=false lock1pid={}",
                            sysinfo::get_current_pid().unwrap()
                        )
                    );

                    let _ = std::fs::remove_file("lock_test.result");
                }
                Ok(Child) => {
                    let lock = create_test_lock("test1.lock");
                    let lock2 = create_test_lock("test2.lock");
                    let pid = read_lock(&PathBuf::from("test1.lock")).unwrap();
                    {
                        let mut result = std::fs::File::create("lock_test.result").unwrap();
                        let _ = result.write_all(
                            format!(
                                "locked1={}, locked2={} lock1pid={}",
                                lock.is_locked().unwrap(),
                                lock2.is_locked().unwrap(),
                                pid,
                            )
                            .as_bytes(),
                        );
                    }
                }
                Err(err) => panic!("Failed to fork: {}", err),
            }
        }
    }
}
