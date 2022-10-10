use anyhow::Result;
use file_guard::{FileGuard, Lock};
use std::fs::File;
use std::path::PathBuf;
use std::rc::Rc;

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
        if let Ok(file) = File::create(&self.path) {
            file_guard::try_lock(&file, Lock::Exclusive, 0, 1).is_err()
        } else {
            false
        }
    }

    /// Try to acquire a lock for this program.
    pub fn acquire(&mut self) -> Result<()> {
        let file = Rc::new(File::create(&self.path)?);

        file_guard::lock(file, Lock::Exclusive, 0, 1)
            .map(|lock| self.lock = Some(lock))
            .map_err(|err| err.into())
    }
}

#[cfg(all(test, unix))]
mod test {
    use super::*;

    fn create_test_lock(name: &str) -> ProgramLock {
        ProgramLock {
            path: PathBuf::new().join(name),
            lock: None,
        }
    }

    #[test]
    fn test_locks() {
        use nix::unistd::{fork, ForkResult::*};
        use std::io::{Read, Write};
        use std::time::Duration;

        // Start we no lock file.
        let _ = std::fs::remove_file("test1.lock");

        let mut lock = create_test_lock("test1.lock");
        assert!(!lock.is_locked());

        lock.acquire().unwrap();

        // Spawn a child process to check we can't get the same lock.
        // assert!() failures in the child are not reported by the test
        // harness, so we write the result in a file from the child and
        // read them back in the parent after a reasonnable delay :(
        unsafe {
            match fork() {
                Ok(Parent { child: _ }) => {
                    let _ = std::fs::remove_file("lock_test.result");

                    std::thread::sleep(Duration::from_secs(1));

                    let mut result = std::fs::File::open("lock_test.result").unwrap();
                    let mut buf = String::new();
                    let _ = result.read_to_string(&mut buf);
                    assert_eq!(buf, "locked1=true, locked2=false");

                    let _ = std::fs::remove_file("lock_test.result");
                }
                Ok(Child) => {
                    let lock = create_test_lock("test1.lock");
                    let lock2 = create_test_lock("test2.lock");
                    {
                        let mut result = std::fs::File::create("lock_test.result").unwrap();
                        let _ = result.write_all(
                            format!(
                                "locked1={}, locked2={}",
                                lock.is_locked(),
                                lock2.is_locked()
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
