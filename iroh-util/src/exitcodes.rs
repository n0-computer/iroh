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
pub type IrohExitCode = i32;

/// Successful exit
pub const OK: IrohExitCode = 0;

/// Generic error exit
pub const ERROR: IrohExitCode = 1;

/// Cannot acquire a resource lock
pub const LOCKED: IrohExitCode = 2;
