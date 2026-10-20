//! End-to-end forwarder tests with no tunnel and no root.
//!
//! A second smoltcp stack plays the app: it sends packets to the forwarder
//! through `push_packets` and receives replies through `PacketIo`. Test
//! addresses are redirected to servers on 127.0.0.1, so real sockets carry
//! the relayed traffic.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use flynn_dataplane::forwarder::{self, ForwarderConfig, ForwarderHandle};
use flynn_dataplane::{
    AppResolver, Clock, CloseReason, DomainBlocklist, Event, EventSink, FlowKey, Host, HostError,
    ModePolicy, NameSource, Notifier, PacketIo, Paths, Policy, SocketProtector,
};
use flynn_proto::{build, ip, transport};
use flynn_rules::{Mode, Verdict};
use flynn_types::AppId;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};

const APP_IP: [u8; 4] = [10, 0, 0, 2];
const ECHO: &str = "198.51.100.1:7";
const TLS: &str = "198.51.100.1:443";
const DNS: &str = "198.51.100.53:53";
const REFUSED: &str = "198.51.100.9:9";
const QUIC: &str = "198.51.100.1:443";

// ----- Host stubs -----------------------------------------------------------

#[derive(Default)]
struct ToApp(Mutex<VecDeque<Vec<u8>>>);

impl PacketIo for ToApp {
    fn write_packets(&self, packets: Vec<Vec<u8>>) -> Result<(), HostError> {
        self.0.lock().unwrap().extend(packets);
        Ok(())
    }
}

struct Stub;
impl SocketProtector for Stub {
    fn protect(&self, _fd: i32) -> bool {
        true
    }
}
impl AppResolver for Stub {
    fn resolve(&self, _flow: &FlowKey) -> Option<AppId> {
        None
    }
}
impl Clock for Stub {
    fn now_unix_millis(&self) -> i64 {
        0
    }
}
impl Paths for Stub {
    fn spool_dir(&self) -> std::path::PathBuf {
        std::env::temp_dir()
    }
    fn rule_snapshot(&self) -> std::path::PathBuf {
        std::env::temp_dir().join("rules.snapshot")
    }
}
impl Notifier for Stub {
    fn notify(&self, _title: &str, _body: &str) {}
}

#[derive(Default)]
struct Collect(Mutex<Vec<Event>>);

impl EventSink for Collect {
    fn emit(&self, event: Event) {
        self.0.lock().unwrap().push(event);
    }
}

impl Collect {
    fn events(&self) -> Vec<Event> {
        self.0.lock().unwrap().clone()
    }

    fn closed(&self) -> Vec<(u64, u64, CloseReason)> {
        self.events()
            .into_iter()
            .filter_map(|e| match e {
                Event::FlowClosed {
                    bytes_up,
                    bytes_down,
                    reason,
                    ..
                } => Some((bytes_up, bytes_down, reason)),
                _ => None,
            })
            .collect()
    }
}

// ----- Local servers --------------------------------------------------------

fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            std::thread::spawn(move || {
                let mut buf = [0u8; 16 * 1024];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// Answers every A query with 198.51.100.1.
fn dns_server() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while let Ok((n, peer)) = socket.recv_from(&mut buf) {
            let Ok(q) = flynn_proto::dns::parse(&buf[..n]) else {
                continue;
            };
            let name = q
                .questions
                .first()
                .map(|q| q.name.clone())
                .unwrap_or_default();
            let reply = build::dns_response(q.id, &name, &[build::DnsRecord::A([198, 51, 100, 1])]);
            let _ = socket.send_to(&reply, peer);
        }
    });
    addr
}

/// Records every datagram it receives, in order.
fn udp_recorder() -> (SocketAddr, Arc<Mutex<Vec<Vec<u8>>>>) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while let Ok((n, _)) = socket.recv_from(&mut buf) {
            log.lock().unwrap().push(buf[..n].to_vec());
        }
    });
    (addr, seen)
}

/// A port nothing listens on.
fn refused_port() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
    // Dropped here, so connects to it are refused.
}

// ----- The app side ---------------------------------------------------------

#[derive(Default)]
struct AppDevice {
    rx: VecDeque<Vec<u8>>,
    tx: Vec<Vec<u8>>,
}

impl Device for AppDevice {
    type RxToken<'a> = AppRx;
    type TxToken<'a> = AppTx<'a>;
    fn receive(&mut self, _: smoltcp::time::Instant) -> Option<(AppRx, AppTx<'_>)> {
        let p = self.rx.pop_front()?;
        Some((AppRx(p), AppTx(&mut self.tx)))
    }
    fn transmit(&mut self, _: smoltcp::time::Instant) -> Option<AppTx<'_>> {
        Some(AppTx(&mut self.tx))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1500;
        caps
    }
}

struct AppRx(Vec<u8>);
impl RxToken for AppRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

struct AppTx<'a>(&'a mut Vec<Vec<u8>>);
impl TxToken for AppTx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut p = vec![0; len];
        let r = f(&mut p);
        self.0.push(p);
        r
    }
}

struct Rig {
    iface: Interface,
    device: AppDevice,
    sockets: SocketSet<'static>,
    to_app: Arc<ToApp>,
    events: Arc<Collect>,
    fwd: Option<ForwarderHandle>,
    epoch: Instant,
    next_port: u16,
    /// Raw UDP packets that came back to the app.
    udp_replies: Vec<Vec<u8>>,
}

impl Rig {
    fn new(policy: Arc<dyn Policy>) -> Self {
        Self::with(policy, |_| {})
    }

    fn with(policy: Arc<dyn Policy>, tweak: impl FnOnce(&mut ForwarderConfig)) -> Self {
        let to_app = Arc::new(ToApp::default());
        let events = Arc::new(Collect::default());
        let host = Host {
            packets: to_app.clone(),
            protector: Arc::new(Stub),
            apps: Arc::new(Stub),
            clock: Arc::new(Stub),
            paths: Arc::new(Stub),
            notifier: Arc::new(Stub),
        };
        let mut config = ForwarderConfig::new(policy);
        config.redirects = HashMap::from([
            (ECHO.parse().unwrap(), echo_server()),
            (TLS.parse().unwrap(), echo_server()),
            (DNS.parse().unwrap(), dns_server()),
            (REFUSED.parse().unwrap(), refused_port()),
        ]);
        tweak(&mut config);
        let fwd = forwarder::spawn(host, config, events.clone()).unwrap();

        let mut device = AppDevice::default();
        let mut iface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut device,
            smoltcp::time::Instant::ZERO,
        );
        let app = Ipv4Address::new(APP_IP[0], APP_IP[1], APP_IP[2], APP_IP[3]);
        iface.update_ip_addrs(|a| {
            let _ = a.push(IpCidr::new(IpAddress::Ipv4(app), 24));
        });
        let _ = iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(10, 0, 0, 1));
        Self {
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
            to_app,
            events,
            fwd: Some(fwd),
            epoch: Instant::now(),
            next_port: 40000,
            udp_replies: Vec::new(),
        }
    }

    fn pump(&mut self) {
        let incoming: Vec<Vec<u8>> = self.to_app.0.lock().unwrap().drain(..).collect();
        for p in incoming {
            match ip::parse(&p) {
                Ok(parsed) if parsed.protocol == ip::PROTO_UDP => self.udp_replies.push(p),
                _ => self.device.rx.push_back(p),
            }
        }
        let now = smoltcp::time::Instant::from_micros(self.epoch.elapsed().as_micros() as i64);
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        let out = std::mem::take(&mut self.device.tx);
        if !out.is_empty() {
            self.fwd.as_ref().unwrap().push_packets(out);
        }
    }

    fn until(&mut self, timeout: Duration, mut done: impl FnMut(&mut Self) -> bool) -> bool {
        let start = Instant::now();
        loop {
            self.pump();
            if done(self) {
                return true;
            }
            if start.elapsed() > timeout {
                return false;
            }
            std::thread::sleep(Duration::from_micros(200));
        }
    }

    fn connect(&mut self, dst: &str) -> SocketHandle {
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 256 * 1024]),
            tcp::SocketBuffer::new(vec![0; 256 * 1024]),
        );
        let dst: SocketAddr = dst.parse().unwrap();
        self.next_port += 1;
        socket
            .connect(
                self.iface.context(),
                (IpAddress::from(dst.ip()), dst.port()),
                self.next_port,
            )
            .unwrap();
        self.sockets.add(socket)
    }

    fn socket(&mut self, handle: SocketHandle) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut::<tcp::Socket>(handle)
    }

    fn send_udp(&mut self, dst: &str, payload: &[u8]) {
        let src: SocketAddr = (std::net::Ipv4Addr::from(APP_IP), 5353).into();
        let packet = build::udp_packet(src, dst.parse().unwrap(), payload);
        self.fwd.as_ref().unwrap().push_packets([packet]);
    }

    fn send_udp_from(&mut self, port: u16, dst: &str, payload: &[u8]) {
        let src: SocketAddr = (std::net::Ipv4Addr::from(APP_IP), port).into();
        let packet = build::udp_packet(src, dst.parse().unwrap(), payload);
        self.fwd.as_ref().unwrap().push_packets([packet]);
    }

    fn stop(&mut self) {
        if let Some(fwd) = self.fwd.take() {
            fwd.stop();
        }
    }
}

// ----- Tests ----------------------------------------------------------------

#[test]
fn tcp_echo_round_trip_and_clean_close() {
    let mut rig = Rig::new(Arc::new(ModePolicy(Mode::AllowAll)));
    let h = rig.connect(ECHO);
    assert!(
        rig.until(Duration::from_secs(5), |r| r.socket(h).may_send()),
        "handshake"
    );

    const TOTAL: usize = 1024 * 1024;
    let payload: Vec<u8> = (0..TOTAL).map(|i| (i % 251) as u8).collect();
    let (mut sent, mut echoed) = (0usize, Vec::with_capacity(TOTAL));
    let start = Instant::now();
    let ok = rig.until(Duration::from_secs(20), |r| {
        let s = r.socket(h);
        if sent < TOTAL && s.can_send() {
            sent += s.send_slice(&payload[sent..]).unwrap();
        }
        while s.can_recv() {
            s.recv(|buf| {
                echoed.extend_from_slice(buf);
                (buf.len(), ())
            })
            .unwrap();
        }
        echoed.len() == TOTAL
    });
    let elapsed = start.elapsed();
    assert!(ok, "echoed {} of {TOTAL} bytes", echoed.len());
    assert!(echoed == payload, "echoed bytes differ");
    eprintln!(
        "1 MiB echoed through the forwarder in {elapsed:?} ({:.1} MB/s each way)",
        TOTAL as f64 / elapsed.as_secs_f64() / 1e6
    );

    rig.socket(h).close();
    assert!(
        rig.until(Duration::from_secs(5), |r| !r.events.closed().is_empty()),
        "flow never closed: {:?}",
        rig.events.events()
    );
    let (up, down, reason) = rig.events.closed()[0];
    assert_eq!((up, down), (TOTAL as u64, TOTAL as u64));
    assert_eq!(reason, CloseReason::Normal);
    rig.stop();
}

#[test]
fn dns_answer_names_a_later_connection() {
    let mut rig = Rig::new(Arc::new(ModePolicy(Mode::AllowAll)));
    rig.send_udp(
        DNS,
        &build::dns_query(0x77, "echo.test", flynn_proto::dns::TYPE_A),
    );
    assert!(
        rig.until(Duration::from_secs(5), |r| !r.udp_replies.is_empty()),
        "no DNS reply"
    );

    // The reply comes back from the address the app asked, not the redirect.
    let reply = ip::parse(&rig.udp_replies[0]).unwrap();
    assert_eq!(
        reply.src,
        "198.51.100.53".parse::<std::net::IpAddr>().unwrap()
    );
    let udp = transport::parse_udp(reply.payload).unwrap();
    assert_eq!((udp.src_port, udp.dst_port), (53, 5353));
    assert_eq!(flynn_proto::dns::parse(udp.payload).unwrap().id, 0x77);

    let h = rig.connect(ECHO);
    assert!(rig.until(Duration::from_secs(5), |r| r.socket(h).may_send()));
    let opened: Vec<_> = rig
        .events
        .events()
        .into_iter()
        .filter_map(|e| match e {
            Event::FlowOpened {
                key, name, source, ..
            } if key.dst.port() == 7 => Some((name, source)),
            _ => None,
        })
        .collect();
    assert_eq!(
        opened,
        vec![(Some("echo.test".to_string()), NameSource::Dns)]
    );
    assert!(
        rig.events
            .events()
            .iter()
            .any(|e| matches!(e, Event::DnsAnswer { name, .. } if name == "echo.test"))
    );
    rig.stop();
}

#[test]
fn server_name_in_client_hello_can_block() {
    let mut rig = Rig::new(Arc::new(DomainBlocklist::new(["blocked.test"])));
    let h = rig.connect(TLS);
    assert!(
        rig.until(Duration::from_secs(5), |r| r.socket(h).may_send()),
        "handshake"
    );
    // Large enough to span two segments, like a post-quantum ClientHello.
    let hello = build::client_hello(Some("www.blocked.test"), 1600);
    rig.socket(h).send_slice(&hello).unwrap();
    assert!(
        rig.until(Duration::from_secs(5), |r| r.socket(h).state()
            == tcp::State::Closed),
        "blocked flow was not reset"
    );
    let events = rig.events.events();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::FlowNamed { name, .. } if name == "www.blocked.test"))
    );
    assert!(rig.until(Duration::from_secs(2), |r| {
        r.events
            .closed()
            .iter()
            .any(|c| c.2 == CloseReason::Blocked)
    }));
    rig.stop();
}

#[test]
fn refused_server_resets_the_app_without_a_handshake() {
    let mut rig = Rig::new(Arc::new(ModePolicy(Mode::AllowAll)));
    let h = rig.connect(REFUSED);
    let mut ever_established = false;
    let closed = rig.until(Duration::from_secs(5), |r| {
        let s = r.socket(h);
        ever_established |= s.may_send();
        s.state() == tcp::State::Closed
    });
    assert!(closed, "app socket never saw the reset");
    assert!(
        !ever_established,
        "app saw a handshake for a refused server"
    );
    assert_eq!(
        rig.events.closed(),
        vec![(0, 0, CloseReason::ConnectFailed)]
    );
    rig.stop();
}

#[test]
fn lockdown_blocks_at_open() {
    let mut rig = Rig::new(Arc::new(ModePolicy(Mode::Lockdown)));
    let h = rig.connect(ECHO);
    assert!(rig.until(Duration::from_secs(5), |r| r.socket(h).state()
        == tcp::State::Closed));
    let verdicts: Vec<Verdict> = rig
        .events
        .events()
        .into_iter()
        .filter_map(|e| match e {
            Event::FlowOpened { verdict, .. } => Some(verdict),
            _ => None,
        })
        .collect();
    assert_eq!(verdicts, vec![Verdict::Block]);
    assert_eq!(rig.events.closed(), vec![(0, 0, CloseReason::Blocked)]);
    rig.stop();
}

// ----- QUIC -----------------------------------------------------------------

fn quic_rig(policy: Arc<dyn Policy>, force_tcp: bool) -> (Rig, Arc<Mutex<Vec<Vec<u8>>>>) {
    let (server, seen) = udp_recorder();
    let rig = Rig::with(policy, |c| {
        c.redirects.insert(QUIC.parse().unwrap(), server);
        c.force_tcp_for_unnamed_quic = force_tcp;
    });
    (rig, seen)
}

fn initials(name: &str) -> Vec<Vec<u8>> {
    let hello = build::client_hello(Some(name), 1500);
    build::quic_initials(flynn_proto::quic::VERSION_1, &[9; 8], &hello[5..], 2)
}

fn closed_reasons(rig: &Rig) -> Vec<CloseReason> {
    rig.events.closed().into_iter().map(|c| c.2).collect()
}

#[test]
fn quic_flow_blocked_by_name_before_any_datagram_leaves() {
    let (mut rig, seen) = quic_rig(Arc::new(DomainBlocklist::new(["blocked.test"])), false);
    for d in initials("www.blocked.test") {
        rig.send_udp_from(60000, QUIC, &d);
    }
    assert!(rig.until(Duration::from_secs(5), |r| {
        closed_reasons(r).contains(&CloseReason::Blocked)
    }));
    // Retransmissions of the blocked flow are dropped without new flows.
    for d in initials("www.blocked.test") {
        rig.send_udp_from(60000, QUIC, &d);
    }
    std::thread::sleep(Duration::from_millis(200));
    rig.pump();
    let events = rig.events.events();
    assert!(events.iter().any(|e| matches!(e, Event::FlowNamed { name, source: NameSource::Sni, .. } if name == "www.blocked.test")));
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, Event::FlowOpened { .. }))
            .count(),
        1
    );
    assert!(
        seen.lock().unwrap().is_empty(),
        "a blocked QUIC flow reached the server"
    );
    rig.stop();
}

#[test]
fn allowed_quic_flow_releases_held_datagrams_in_order() {
    let (mut rig, seen) = quic_rig(Arc::new(DomainBlocklist::new(["blocked.test"])), false);
    let sent = initials("api.example.org");
    for d in &sent {
        rig.send_udp_from(60001, QUIC, d);
    }
    assert!(rig.until(Duration::from_secs(5), |_| seen.lock().unwrap().len() == 2));
    assert_eq!(*seen.lock().unwrap(), sent);
    assert!(
        rig.events
            .events()
            .iter()
            .any(|e| matches!(e, Event::FlowNamed { name, .. } if name == "api.example.org"))
    );
    rig.stop();
}

#[test]
fn unnamed_quic_is_dropped_only_when_forcing_tcp() {
    // Looks like a v1 Initial but cannot be decrypted, so it stays unnamed.
    let mut fake = vec![0xc3, 0, 0, 0, 1, 8];
    fake.resize(1200, 0x5a);

    let (mut rig, seen) = quic_rig(Arc::new(ModePolicy(Mode::AllowAll)), true);
    rig.send_udp_from(60002, QUIC, &fake);
    assert!(rig.until(Duration::from_secs(5), |r| {
        closed_reasons(r).contains(&CloseReason::ForcedTcp)
    }));
    assert!(seen.lock().unwrap().is_empty());
    rig.stop();

    let (mut rig, seen) = quic_rig(Arc::new(ModePolicy(Mode::AllowAll)), false);
    rig.send_udp_from(60003, QUIC, &fake);
    assert!(
        rig.until(Duration::from_secs(5), |_| seen.lock().unwrap().len() == 1),
        "unnamed QUIC was not released"
    );
    rig.stop();
}
