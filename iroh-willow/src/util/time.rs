use std::time::SystemTime;

/// Returns the current system time in microseconds since [`SystemTime::UNIX_EPOCH`].
pub fn system_time_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("time drift")
        .as_micros() as u64
}
