//! Parsers for the packets the data plane reads.
//!
//! Every input here is hostile: it arrives from any app and any server.
//! Parsers take borrowed slices, never panic, and avoid allocating except
//! for DNS names. Each parser has a fuzz target in `core/fuzz` and a
//! no-panic property test in `tests/no_panic.rs`.

pub mod build;
pub mod dns;
pub mod ip;
pub mod quic;
pub mod tls;
pub mod transport;

pub use ip::{IpPacket, IpVersion, ip_version};
