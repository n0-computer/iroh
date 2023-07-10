//! Firewall integrations.

#[cfg(target_os = "windows")]
pub mod fwpm;
#[cfg(target_os = "windows")]
pub mod windows;
