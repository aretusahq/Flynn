//! UniFFI bindings for every host.
//!
//! One crate, two facades: [`FlynnDataPlane`] for capture extensions and
//! (from M5) a Library facade for the app. Swift and Kotlin are both
//! generated from this file; hosts implement the `Host*` traits to supply
//! platform behaviour.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use flynn_dataplane as dp;
use flynn_types::{AppId, Capabilities, LeakScope, Platform};

uniffi::setup_scaffolding!();

/// Version of the Rust core, shown in the app's about screen and logs.
#[uniffi::export]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// Shared types, re-declared for UniFFI from flynn-types.

#[uniffi::remote(Enum)]
pub enum Platform {
    Ios,
    Android,
    Macos,
    Windows,
    Linux,
}

#[uniffi::remote(Enum)]
pub enum LeakScope {
    None,
    Device,
    PerApp,
}

#[uniffi::remote(Record)]
pub struct AppId {
    pub platform: Platform,
    pub id: String,
    pub display_name: Option<String>,
}

#[uniffi::remote(Record)]
pub struct Capabilities {
    pub per_app_available: bool,
    pub can_pause_flow: bool,
    pub leak_detection_scope: LeakScope,
}

#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum Transport {
    Tcp,
    Udp,
}

/// A flow's five-tuple, passed to hosts as strings so neither Swift nor
/// Kotlin needs a socket-address type.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FlowKey {
    pub transport: Transport,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
}

// Host traits, implemented in Swift or Kotlin.

#[uniffi::export(with_foreign)]
pub trait HostPacketIo: Send + Sync {
    /// Returns false if the host could not write the packets.
    fn write_packets(&self, packets: Vec<Vec<u8>>) -> bool;
}

#[uniffi::export(with_foreign)]
pub trait HostSocketProtector: Send + Sync {
    fn protect(&self, fd: i32) -> bool;
}

#[uniffi::export(with_foreign)]
pub trait HostAppResolver: Send + Sync {
    fn resolve(&self, flow: FlowKey) -> Option<AppId>;
}

#[uniffi::export(with_foreign)]
pub trait HostClock: Send + Sync {
    fn now_unix_millis(&self) -> i64;
}

#[uniffi::export(with_foreign)]
pub trait HostPaths: Send + Sync {
    fn spool_dir(&self) -> String;
    fn rule_snapshot(&self) -> String;
}

#[uniffi::export(with_foreign)]
pub trait HostNotifier: Send + Sync {
    fn notify(&self, title: String, body: String);
}

/// The data plane, as seen by a capture extension.
#[derive(uniffi::Object)]
pub struct FlynnDataPlane {
    inner: Mutex<dp::DataPlane>,
}

#[uniffi::export]
impl FlynnDataPlane {
    #[uniffi::constructor]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        packets: Arc<dyn HostPacketIo>,
        protector: Arc<dyn HostSocketProtector>,
        apps: Arc<dyn HostAppResolver>,
        clock: Arc<dyn HostClock>,
        paths: Arc<dyn HostPaths>,
        notifier: Arc<dyn HostNotifier>,
        capabilities: Capabilities,
    ) -> Arc<Self> {
        let host = dp::Host {
            packets: Arc::new(PacketIoAdapter(packets)),
            protector: Arc::new(SocketProtectorAdapter(protector)),
            apps: Arc::new(AppResolverAdapter(apps)),
            clock: Arc::new(ClockAdapter(clock)),
            paths: Arc::new(PathsAdapter(paths)),
            notifier: Arc::new(NotifierAdapter(notifier)),
        };
        Arc::new(Self {
            inner: Mutex::new(dp::DataPlane::new(host, capabilities)),
        })
    }

    pub fn capabilities(&self) -> Capabilities {
        self.lock().capabilities()
    }

    pub fn set_capabilities(&self, capabilities: Capabilities) {
        self.lock().set_capabilities(capabilities);
    }
}

impl FlynnDataPlane {
    fn lock(&self) -> std::sync::MutexGuard<'_, dp::DataPlane> {
        // A poisoned lock means a panic mid-update; the extension aborts on
        // panic in release, so recovering the guard is only for tests.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

// Adapters from the FFI host traits to the data plane's own traits.

struct PacketIoAdapter(Arc<dyn HostPacketIo>);
impl dp::PacketIo for PacketIoAdapter {
    fn write_packets(&self, packets: Vec<Vec<u8>>) -> Result<(), dp::HostError> {
        if self.0.write_packets(packets) {
            Ok(())
        } else {
            Err(dp::HostError::Rejected("write_packets".into()))
        }
    }
}

struct SocketProtectorAdapter(Arc<dyn HostSocketProtector>);
impl dp::SocketProtector for SocketProtectorAdapter {
    fn protect(&self, fd: i32) -> bool {
        self.0.protect(fd)
    }
}

struct AppResolverAdapter(Arc<dyn HostAppResolver>);
impl dp::AppResolver for AppResolverAdapter {
    fn resolve(&self, flow: &dp::FlowKey) -> Option<AppId> {
        self.0.resolve(flow.into())
    }
}

struct ClockAdapter(Arc<dyn HostClock>);
impl dp::Clock for ClockAdapter {
    fn now_unix_millis(&self) -> i64 {
        self.0.now_unix_millis()
    }
}

struct PathsAdapter(Arc<dyn HostPaths>);
impl dp::Paths for PathsAdapter {
    fn spool_dir(&self) -> PathBuf {
        self.0.spool_dir().into()
    }
    fn rule_snapshot(&self) -> PathBuf {
        self.0.rule_snapshot().into()
    }
}

struct NotifierAdapter(Arc<dyn HostNotifier>);
impl dp::Notifier for NotifierAdapter {
    fn notify(&self, title: &str, body: &str) {
        self.0.notify(title.to_string(), body.to_string());
    }
}

impl From<&dp::FlowKey> for FlowKey {
    fn from(key: &dp::FlowKey) -> Self {
        let ip = |addr: SocketAddr| -> String {
            match addr.ip() {
                IpAddr::V4(v4) => v4.to_string(),
                IpAddr::V6(v6) => v6.to_string(),
            }
        };
        Self {
            transport: match key.protocol {
                dp::Transport::Tcp => Transport::Tcp,
                dp::Transport::Udp => Transport::Udp,
            },
            src_ip: ip(key.src),
            src_port: key.src.port(),
            dst_ip: ip(key.dst),
            dst_port: key.dst.port(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Null;
    impl HostPacketIo for Null {
        fn write_packets(&self, _: Vec<Vec<u8>>) -> bool {
            true
        }
    }
    impl HostSocketProtector for Null {
        fn protect(&self, _: i32) -> bool {
            true
        }
    }
    impl HostAppResolver for Null {
        fn resolve(&self, _: FlowKey) -> Option<AppId> {
            None
        }
    }
    impl HostClock for Null {
        fn now_unix_millis(&self) -> i64 {
            0
        }
    }
    impl HostPaths for Null {
        fn spool_dir(&self) -> String {
            "/tmp/spool".into()
        }
        fn rule_snapshot(&self) -> String {
            "/tmp/rules.bin".into()
        }
    }
    impl HostNotifier for Null {
        fn notify(&self, _: String, _: String) {}
    }

    #[test]
    fn data_plane_round_trips_capabilities() {
        let null = Arc::new(Null);
        let plane = FlynnDataPlane::new(
            null.clone(),
            null.clone(),
            null.clone(),
            null.clone(),
            null.clone(),
            null,
            Capabilities::TUNNEL_ONLY,
        );
        assert_eq!(plane.capabilities(), Capabilities::TUNNEL_ONLY);
        let supervised = Capabilities {
            per_app_available: true,
            can_pause_flow: true,
            ..Capabilities::TUNNEL_ONLY
        };
        plane.set_capabilities(supervised);
        assert_eq!(plane.capabilities(), supervised);
    }

    #[test]
    fn flow_key_formats_addresses() {
        let key = dp::FlowKey {
            protocol: dp::Transport::Udp,
            src: "[fd00::2]:5353".parse().unwrap(),
            dst: "1.1.1.1:53".parse().unwrap(),
        };
        let ffi: FlowKey = (&key).into();
        assert_eq!(ffi.src_ip, "fd00::2");
        assert_eq!(ffi.dst_ip, "1.1.1.1");
        assert_eq!(ffi.dst_port, 53);
    }
}
