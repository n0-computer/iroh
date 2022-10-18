//! iroh exit codes
//!
//! Exit code constants intended to be passed to
//! `std::process::exit()`
//!
//! # Example:
//! ```
//! extern crate exitcode;
//!
//! ::std::process::exit(exitcode::OK);
//! ```

/// Alias for the numeric type that holds system exit codes.
pub type ExitCode = i32;

/// Successful exit
pub const OK: ExitCode = 0;

/// Generic error exit
pub const ERROR: ExitCode = 1;

/// Cannot acquire a resource lock
pub const LOCKED: ExitCode = 2;