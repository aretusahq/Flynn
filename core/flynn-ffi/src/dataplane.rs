//! The capture-extension facade: host traits in, forwarder out.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use flynn_dataplane::spool::SpoolSink;
use flynn_dataplane::{
    self as dp, ForwarderConfig, ForwarderHandle, Policy, RulesPolicy, StatsSnapshot, Transport,
};
use flynn_rules::RuleSet;
use flynn_types::{AppId, Capabilities};

use crate::{FlynnError, RulesInfo, rules::info_of};

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
        mtu: 1500,
        tcp_recv_buffer_kib: 16,
        tcp_send_buffer_kib: 32,
        sample_every_secs: 10,
        force_tcp_for_unnamed_quic: false,
        dns_redirect: None,
    }
}

impl ForwarderSettings {
    fn to_config(&self, policy: Arc<dyn Policy>) -> Result<ForwarderConfig, FlynnError> {
        let invalid = |message: String| FlynnError::InvalidSettings { message };
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
    policy: Arc<RulesPolicy>,
}

/// What starting the forwarder found.
#[derive(Debug, Clone, uniffi::Record)]
pub struct StartReport {
    /// The rules the forwarder starts with.
    pub rules: RulesInfo,
    /// Set when the rules file exists but could not be used (damaged, or a
    /// version this build does not read). The forwarder then runs
    /// allow-all, and the host should tell the user.
    pub rules_error: Option<String>,
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

    /// Starts the forwarder thread, writing events to the spool, with the
    /// rules in the snapshot file (allow-all if there is none).
    pub fn start(&self, settings: ForwarderSettings) -> Result<StartReport, FlynnError> {
        let mut running = self.running.write().unwrap_or_else(|e| e.into_inner());
        if running.is_some() {
            return Err(FlynnError::AlreadyRunning);
        }
        let plane = self.lock();
        let (initial, rules_error) = match dp::load_rules(&plane.host().paths.rule_snapshot()) {
            Ok(Some(rules)) => (rules, None),
            Ok(None) => (RuleSet::allow_all(), None),
            Err(e) => (RuleSet::allow_all(), Some(e.to_string())),
        };
        let report = StartReport {
            rules: info_of(&initial),
            rules_error,
        };
        let policy = Arc::new(RulesPolicy::new(initial));
        let config = settings.to_config(policy.clone())?;
        let sink = Arc::new(SpoolSink::open(&plane.host().paths.spool_dir())?);
        let handle = plane.start(config, sink.clone())?;
        *running = Some(Running {
            handle,
            sink,
            policy,
        });
        Ok(report)
    }

    /// Reads the snapshot file again and swaps its rules in without
    /// restarting anything. Flows already open are checked against them at
    /// once: a flow the new rules block is reset. A missing file means
    /// allow-all; a damaged one is an error and the current rules stay.
    pub fn reload_rules(&self) -> Result<RulesInfo, FlynnError> {
        let running = self.running.read().unwrap_or_else(|e| e.into_inner());
        let Some(r) = running.as_ref() else {
            return Err(FlynnError::Io {
                message: "the data plane is not running".into(),
            });
        };
        let path = self.lock().host().paths.rule_snapshot();
        let rules = match dp::load_rules(&path) {
            Ok(Some(rules)) => rules,
            Ok(None) => RuleSet::allow_all(),
            Err(e) => {
                return Err(FlynnError::InvalidRules {
                    message: e.to_string(),
                });
            }
        };
        let info = info_of(&rules);
        r.policy.replace(rules);
        r.handle.wake();
        Ok(info)
    }

    /// The rules in force, or `None` while not running.
    pub fn rules_info(&self) -> Option<RulesInfo> {
        let running = self.running.read().ok()?;
        Some(info_of(&running.as_ref()?.policy.rules()))
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
            s.to_config(Arc::new(RulesPolicy::allow_all())),
            Err(FlynnError::InvalidSettings { .. })
        ));
    }

    fn lockdown_snapshot(dir: &std::path::Path, generation: u64) {
        let config = crate::parse_rules_text("mode lockdown\n".into()).unwrap();
        crate::write_rule_snapshot(
            dir.join("rules.snapshot").to_string_lossy().into_owned(),
            config,
            generation,
        )
        .unwrap();
    }

    fn udp_to(port: u16) -> Vec<u8> {
        flynn_proto::build::udp_packet(
            "10.0.0.2:5000".parse().unwrap(),
            format!("127.0.0.1:{port}").parse().unwrap(),
            b"x",
        )
    }

    #[test]
    fn start_loads_the_rules_file_and_reload_swaps_it_live() {
        let dir = std::env::temp_dir().join(format!("flynn-ffi-rules-live-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = plane(&dir);
        assert_eq!(p.rules_info(), None, "not running yet");

        // No file: allow-all, and no complaint.
        let report = p.start(default_forwarder_settings()).unwrap();
        assert_eq!(report.rules.mode, flynn_rules::Mode::AllowAll);
        assert_eq!(report.rules_error, None);
        p.push_packets(vec![udp_to(9)]);
        std::thread::sleep(Duration::from_millis(100));

        // Lockdown written and reloaded: new flows are blocked at once.
        lockdown_snapshot(&dir, 11);
        let info = p.reload_rules().unwrap();
        assert_eq!(
            (info.mode, info.generation),
            (flynn_rules::Mode::Lockdown, 11)
        );
        assert_eq!(p.rules_info(), Some(info));
        p.push_packets(vec![udp_to(10)]);
        std::thread::sleep(Duration::from_millis(100));

        // A damaged file is refused and the current rules stay.
        let path = dir.join("rules.snapshot");
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&path, bytes).unwrap();
        assert!(matches!(
            p.reload_rules(),
            Err(FlynnError::InvalidRules { .. })
        ));
        assert_eq!(p.rules_info().unwrap().mode, flynn_rules::Mode::Lockdown);

        p.stop();
        let events = spool_tail(dir.to_string_lossy().into_owned(), 200).unwrap();
        let opened = |port: &str, verdict: flynn_rules::Verdict| {
            events.iter().any(|e| {
                matches!(e, SpoolEvent::FlowOpened { dst, verdict: v, .. }
                    if dst.ends_with(port) && *v == verdict)
            })
        };
        assert!(opened(":9", flynn_rules::Verdict::Allow));
        assert!(opened(":10", flynn_rules::Verdict::Block));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_damaged_rules_file_at_start_runs_allow_all_and_says_so() {
        let dir = std::env::temp_dir().join(format!("flynn-ffi-rules-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("rules.snapshot"),
            b"definitely not a snapshot, but long enough",
        )
        .unwrap();
        let p = plane(&dir);
        let report = p.start(default_forwarder_settings()).unwrap();
        assert_eq!(report.rules.mode, flynn_rules::Mode::AllowAll);
        assert!(report.rules_error.is_some());
        p.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reload_needs_a_running_data_plane() {
        let p = plane(&std::env::temp_dir());
        assert!(p.reload_rules().is_err());
    }
}
