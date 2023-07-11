//! Utilities for probing [NAT-PMP](https://datatracker.ietf.org/doc/html/rfc6886) and
//! [PCP](https://datatracker.ietf.org/doc/html/rfc6887).

#![allow(unused)]

// NOTES
// TODO(@divma): move to pr desc
// PCP has multicast announcements from the server to the clients, this means binding to
// 224.0.0.1:CLIENT_PORT. to implement or not to implement.

mod protocol;
