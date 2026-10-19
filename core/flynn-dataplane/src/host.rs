//! What the data plane needs from the platform it runs on.
//!
//! Each host (the iOS packet tunnel, the iOS content filter, later the
//! Android VpnService) implements these traits. They are the only place
//! platform behaviour enters the core; nothing else in `core/` may know which
//! OS it is on.

use std::path::PathBuf;

use flynn_types::AppId;

/// Raw IP packets in and out of the tunnel interface.
/// iOS: `NEPacketTunnelFlow`. Android: the TUN file descriptor.
pub trait PacketIo: Send + Sync {
    /// Writes packets back towards the apps on the device.
    fn write_packets(&self, packets: Vec<Vec<u8>>) -> Result<(), HostError>;
}

/// Called on every outbound socket the forwarder opens, before it connects.
/// iOS: a no-op, the extension's own sockets bypass its tunnel.
/// Android: `VpnService.protect(fd)`, without which our traffic loops back
/// into our own tunnel.
pub trait SocketProtector: Send + Sync {
    fn protect(&self, fd: i32) -> bool;
}

/// Maps a flow to the app that opened it, where the host can tell.
/// iOS: the content filter's source app identifier, or `None` at tunnel
/// level. Android: the connection-owner UID resolved to a package name.
pub trait AppResolver: Send + Sync {
    fn resolve(&self, flow: &FlowKey) -> Option<AppId>;
}

/// Wall-clock time, injectable so tests and pcap replay are deterministic.
pub trait Clock: Send + Sync {
    fn now_unix_millis(&self) -> i64;
}

/// Where shared files live. iOS: the App Group container. Android: the app's
/// files directory.
pub trait Paths: Send + Sync {
    /// Directory the event spool segments are written to.
    fn spool_dir(&self) -> PathBuf;
    /// Path of the compiled rule snapshot written by the app.
    fn rule_snapshot(&self) -> PathBuf;
}

/// Posts user-facing alerts from the capture process, where the host allows it.
pub trait Notifier: Send + Sync {
    fn notify(&self, title: &str, body: &str);
}

/// The transport five-tuple identifying a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub protocol: Transport,
    pub src: std::net::SocketAddr,
    pub dst: std::net::SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    Tcp,
    Udp,
}

#[derive(Debug, thiserror::Error)]
pub enum HostError {
    #[error("the host rejected the operation: {0}")]
    Rejected(String),
}
