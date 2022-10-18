use anyhow::{anyhow, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use file_guard::{FileGuard, Lock};
use std::fs::File;
use std::path::PathBuf;
use std::process;
use std::rc::Rc;
use tracing::info;

/// Manages a lock file used to track if an iroh program
/// is already running.
/// The lock is released either when the object is dropped
/// or when the program stops.
pub struct ProgramLock {
    path: PathBuf,
    lock: Option<FileGuard<Rc<File>>>,
}

impl ProgramLock {
    /// Create a new lock for the given program. This does not yet acquire the lock.
    pub fn new(prog_name: &str) -> Result<Self> {
        let path = crate::iroh_data_path(&format!("{}.lock", prog_name))?;
        Ok(Self { path, lock: None })
    }

    /// Check if the current program is locked or not.
    pub fn is_locked(&self) -> bool {
        if !self.path.exists() {
            return false;
        }

        // Even if we manage to lock the file this won't last since the drop implementation
        // of FileGuard releases the underlying lock.
        if let Ok(file) = File::open(&self.path) {
            file_guard::try_lock(&file, Lock::Exclusive, 0, 1).is_err()
        } else {
            false
        }
    }

    /// Try to acquire a lock for this program.
    pub fn acquire(&mut self) -> Result<()> {
        let mut file = File::create(&self.path)?;
        file.write_u32::<LittleEndian>(process::id())?;
        let file = Rc::new(file);

        file_guard::lock(file, Lock::Exclusive, 0, 1)
            .map(|lock| self.lock = Some(lock))
            .map_err(|err| err.into())
    }
}

/// Attempt to remove a stray lock file that wasn't cleaned up, returns true
/// if a lock is successfully deleted, and will only attempt to delete if the
/// lock is not currently held
pub fn try_cleanup_dead_lock(prog_name: &str) -> Result<bool> {
    let lock = ProgramLock {
        path: crate::iroh_data_path(&format!("{}.lock", prog_name))?,
        lock: None,
    };
    if lock.is_locked() {
        info!("lock {} is currently active, cannot remove", prog_name);
        return Ok(false);
    }
    match std::fs::remove_file(lock.path) {
        Err(e) => {
            info!("error removing {} lockfile: {}", prog_name, e);
            Ok(false)
        }
        Ok(_) => {
            info!("removed dead {} lockfile", prog_name);
            Ok(true)
        }
    }
}

/// Report Process ID stored in a lock file
pub fn read_lock_pid(prog_name: &str) -> Result<u32> {
    let path = crate::iroh_data_path(&format!("{}.lock", prog_name))?;
    read_lock(path)
}

fn read_lock(path: PathBuf) -> Result<u32> {
    if !path.exists() {
        return Err(anyhow!("no lock file exists"));
    }
    let mut file = File::open(path)?;
    let pid = file.read_u32::<LittleEndian>()?;
    Ok(pid)
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
    fn test_locks() {
        use nix::unistd::{fork, ForkResult::*};
        use std::io::{Read, Write};
        use std::time::Duration;

        // Start with no lock file.
        let _ = std::fs::remove_file("test1.lock");

        let mut lock = create_test_lock("test1.lock");
        assert!(!lock.is_locked());
        assert!(read_lock(PathBuf::from("test1.lock")).is_err());

        lock.acquire().unwrap();

        assert!(lock.is_locked());
        // ensure call to is_locked doesn't affect PID reporting
        assert_eq!(
            process::id(),
            read_lock(PathBuf::from("test1.lock")).unwrap()
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
                        format!("locked1=true, locked2=false lock1pid={}", process::id())
                    );

                    let _ = std::fs::remove_file("lock_test.result");
                }
                Ok(Child) => {
                    let lock = create_test_lock("test1.lock");
                    let lock2 = create_test_lock("test2.lock");
                    let pid = read_lock(PathBuf::from("test1.lock")).unwrap();
                    {
                        let mut result = std::fs::File::create("lock_test.result").unwrap();
                        let _ = result.write_all(
                            format!(
                                "locked1={}, locked2={} lock1pid={}",
                                lock.is_locked(),
                                lock2.is_locked(),
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
