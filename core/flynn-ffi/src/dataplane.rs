//! The capture-extension facade: host traits in, forwarder out.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use flynn_dataplane::spool::SpoolSink;
use flynn_dataplane::{
    self as dp, DomainBlocklist, ForwarderConfig, ForwarderHandle, StatsSnapshot, Transport,
};
use flynn_rules::Mode;
use flynn_types::{AppId, Capabilities};

use crate::FlynnError;

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

impl From<&dp::FlowKey> for FlowKey {
    fn from(key: &dp::FlowKey) -> Self {
        Self {
            transport: key.protocol,
            src_ip: key.src.ip().to_string(),
            src_port: key.src.port(),
            dst_ip: key.dst.ip().to_string(),
            dst_port: key.dst.port(),
        }
    }
}

/// How the forwarder runs. Start from [`default_forwarder_settings`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct ForwarderSettings {
    pub mode: Mode,
    /// Domains (and their subdomains) to block whatever the mode.
    pub blocked_domains: Vec<String>,
    pub mtu: u32,
    pub tcp_recv_buffer_kib: u32,
    pub tcp_send_buffer_kib: u32,
    pub sample_every_secs: u32,
    /// Drop QUIC flows whose name cannot be read, so apps retry over TCP.
    pub force_tcp_for_unnamed_quic: bool,
    /// Send DNS addressed to a virtual resolver to a real one instead.
    pub dns_redirect: Option<DnsRedirect>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct DnsRedirect {
    /// The resolver address given to the OS, "ip:port".
    pub virtual_addr: String,
    /// Where those queries really go, "ip:port".
    pub upstream: String,
}

#[uniffi::export]
pub fn default_forwarder_settings() -> ForwarderSettings {
    ForwarderSettings {
        mode: Mode::AllowAll,
        blocked_domains: Vec::new(),
        mtu: 1500,
        tcp_recv_buffer_kib: 16,
        tcp_send_buffer_kib: 32,
        sample_every_secs: 10,
        force_tcp_for_unnamed_quic: false,
        dns_redirect: None,
    }
}

impl ForwarderSettings {
    fn to_config(&self) -> Result<ForwarderConfig, FlynnError> {
        let invalid = |message: String| FlynnError::InvalidSettings { message };
        let policy =
            Arc::new(DomainBlocklist::new(self.blocked_domains.clone()).with_mode(self.mode));
        let mut config = ForwarderConfig::new(policy);
        if !(576..=65535).contains(&self.mtu) {
            return Err(invalid(format!("mtu {} out of range", self.mtu)));
        }
        config.mtu = self.mtu as usize;
        config.tcp_recv_buffer = (self.tcp_recv_buffer_kib.clamp(4, 1024) as usize) * 1024;
        config.tcp_send_buffer = (self.tcp_send_buffer_kib.clamp(4, 1024) as usize) * 1024;
        config.sample_every = Duration::from_secs(u64::from(self.sample_every_secs.max(1)));
        config.force_tcp_for_unnamed_quic = self.force_tcp_for_unnamed_quic;
        if let Some(r) = &self.dns_redirect {
            let parse = |s: &str| {
                s.parse::<SocketAddr>()
                    .map_err(|_| invalid(format!("not an ip:port: {s}")))
            };
            config.redirects = HashMap::from([(parse(&r.virtual_addr)?, parse(&r.upstream)?)]);
        }
        Ok(config)
    }
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

struct Running {
    handle: ForwarderHandle,
    sink: Arc<SpoolSink>,
}

/// The data plane, as seen by a capture extension.
#[derive(uniffi::Object)]
pub struct FlynnDataPlane {
    inner: Mutex<dp::DataPlane>,
    running: RwLock<Option<Running>>,
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
            running: RwLock::new(None),
        })
    }

    pub fn capabilities(&self) -> Capabilities {
        self.lock().capabilities()
    }

    pub fn set_capabilities(&self, capabilities: Capabilities) {
        self.lock().set_capabilities(capabilities);
    }

    /// Starts the forwarder thread, writing events to the spool.
    pub fn start(&self, settings: ForwarderSettings) -> Result<(), FlynnError> {
        let mut running = self.running.write().unwrap_or_else(|e| e.into_inner());
        if running.is_some() {
            return Err(FlynnError::AlreadyRunning);
        }
        let config = settings.to_config()?;
        let plane = self.lock();
        let sink = Arc::new(SpoolSink::open(&plane.host().paths.spool_dir())?);
        let handle = plane.start(config, sink.clone())?;
        *running = Some(Running { handle, sink });
        Ok(())
    }

    /// Hands packets read from the tunnel to the forwarder. Dropped when
    /// the forwarder is not running.
    pub fn push_packets(&self, packets: Vec<Vec<u8>>) {
        let running = self.running.read().unwrap_or_else(|e| e.into_inner());
        if let Some(r) = running.as_ref() {
            r.handle.push_packets(packets);
        }
    }

    /// Stops the forwarder, resetting open connections, and flushes the spool.
    pub fn stop(&self) {
        let taken = self
            .running
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(r) = taken {
            r.handle.stop();
            r.sink.flush();
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.read().map(|r| r.is_some()).unwrap_or(false)
    }

    pub fn stats(&self) -> Option<StatsSnapshot> {
        self.running.read().ok()?.as_ref().map(|r| r.handle.stats())
    }

    /// Spool write failures since start.
    pub fn spool_errors(&self) -> u64 {
        self.running
            .read()
            .ok()
            .and_then(|r| r.as_ref().map(|r| r.sink.errors()))
            .unwrap_or(0)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::{SpoolEvent, spool_tail};

    struct Null(PathBuf);
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
            self.0.to_string_lossy().into_owned()
        }
        fn rule_snapshot(&self) -> String {
            self.0.join("rules.snapshot").to_string_lossy().into_owned()
        }
    }
    impl HostNotifier for Null {
        fn notify(&self, _: String, _: String) {}
    }

    fn plane(dir: &std::path::Path) -> Arc<FlynnDataPlane> {
        let null = Arc::new(Null(dir.to_path_buf()));
        FlynnDataPlane::new(
            null.clone(),
            null.clone(),
            null.clone(),
            null.clone(),
            null.clone(),
            null,
            Capabilities::TUNNEL_ONLY,
        )
    }

    #[test]
    fn data_plane_round_trips_capabilities() {
        let p = plane(&std::env::temp_dir());
        assert_eq!(p.capabilities(), Capabilities::TUNNEL_ONLY);
        let supervised = Capabilities {
            per_app_available: true,
            can_pause_flow: true,
            ..Capabilities::TUNNEL_ONLY
        };
        p.set_capabilities(supervised);
        assert_eq!(p.capabilities(), supervised);
    }

    #[test]
    fn start_writes_a_sample_to_the_spool_and_stop_flushes_it() {
        let dir = std::env::temp_dir().join(format!("flynn-ffi-spool-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let p = plane(&dir);
        p.start(default_forwarder_settings()).unwrap();
        assert!(matches!(
            p.start(default_forwarder_settings()),
            Err(FlynnError::AlreadyRunning)
        ));
        // A UDP packet the forwarder will open a flow for.
        p.push_packets(vec![flynn_proto::build::udp_packet(
            "10.0.0.2:5000".parse().unwrap(),
            "127.0.0.1:9".parse().unwrap(),
            b"x",
        )]);
        std::thread::sleep(Duration::from_millis(100));
        assert!(p.stats().unwrap().packets_in >= 1);
        p.stop();
        assert!(!p.is_running());

        let events = spool_tail(dir.to_string_lossy().into_owned(), 100).unwrap();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, SpoolEvent::Sample { mem, .. } if mem.footprint > 0))
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, SpoolEvent::FlowOpened { dst, .. } if dst == "127.0.0.1:9"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_bad_settings() {
        let mut s = default_forwarder_settings();
        s.dns_redirect = Some(DnsRedirect {
            virtual_addr: "nope".into(),
            upstream: "1.1.1.1:53".into(),
        });
        assert!(matches!(
            s.to_config(),
            Err(FlynnError::InvalidSettings { .. })
        ));
    }
}
