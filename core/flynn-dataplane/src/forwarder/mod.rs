//! The userspace forwarder: terminates each app connection locally and
//! opens a matching one to the real server.
//!
//! One thread runs a mio event loop beside a smoltcp interface in any-IP
//! mode. TCP from apps goes through smoltcp; UDP is relayed directly. The
//! host pushes tunnel packets in with [`ForwarderHandle::push_packets`] and
//! receives packets for apps through [`PacketIo`](crate::PacketIo).

mod device;
mod net;
mod tcp;
mod udp;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use flynn_proto::{ip, transport};
use flynn_rules::Verdict;
use mio::{Events, Interest, Poll, Token, Waker};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer};
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpListenEndpoint, Ipv4Address, Ipv6Address,
};

use crate::events::{CloseReason, Event, EventSink, FlowId};
use crate::names::{DnsCache, NameSource};
use crate::policy::{FlowMeta, Policy};
use crate::{FlowKey, Host, Transport};

use device::TunDevice;
use tcp::{PendingTcp, RelayCtx, TcpFlow};
use udp::UdpFlow;

const WAKER: Token = Token(0);

pub struct ForwarderConfig {
    pub policy: Arc<dyn Policy>,
    /// Destinations to connect somewhere else: a virtual DNS address to the
    /// real resolver, or test addresses to local servers.
    pub redirects: HashMap<SocketAddr, SocketAddr>,
    pub mtu: usize,
    /// Per-connection buffer for app-to-server bytes (the app's send window).
    pub tcp_recv_buffer: usize,
    /// Per-connection buffer for server-to-app bytes.
    pub tcp_send_buffer: usize,
    pub connect_timeout: Duration,
    pub udp_idle: Duration,
    /// How long a DNS flow stays open after its first answer.
    pub dns_idle: Duration,
    pub max_tcp_flows: usize,
    pub max_udp_flows: usize,
    pub dns_cache_size: usize,
    /// How long to hold a partial ClientHello waiting for the server name.
    pub sni_wait: Duration,
}

impl ForwarderConfig {
    pub fn new(policy: Arc<dyn Policy>) -> Self {
        Self {
            policy,
            redirects: HashMap::new(),
            mtu: 1500,
            tcp_recv_buffer: 16 * 1024,
            tcp_send_buffer: 32 * 1024,
            connect_timeout: Duration::from_secs(10),
            udp_idle: Duration::from_secs(60),
            dns_idle: Duration::from_secs(5),
            max_tcp_flows: 1024,
            max_udp_flows: 1024,
            dns_cache_size: 4096,
            sni_wait: Duration::from_millis(500),
        }
    }
}

/// Counters readable from any thread while the forwarder runs.
#[derive(Default)]
struct Stats {
    packets_in: AtomicU64,
    packets_out: AtomicU64,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
    tcp_active: AtomicU64,
    udp_active: AtomicU64,
    flows_opened: AtomicU64,
    flows_blocked: AtomicU64,
    connect_failed: AtomicU64,
    dropped: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub packets_in: u64,
    pub packets_out: u64,
    /// Payload bytes relayed app to server.
    pub bytes_up: u64,
    /// Payload bytes relayed server to app.
    pub bytes_down: u64,
    pub tcp_active: u64,
    pub udp_active: u64,
    pub flows_opened: u64,
    pub flows_blocked: u64,
    pub connect_failed: u64,
    /// Packets that were not TCP or UDP, were fragments, or failed to parse.
    pub dropped: u64,
}

impl Stats {
    fn snapshot(&self) -> StatsSnapshot {
        let r = |a: &AtomicU64| a.load(Ordering::Relaxed);
        StatsSnapshot {
            packets_in: r(&self.packets_in),
            packets_out: r(&self.packets_out),
            bytes_up: r(&self.bytes_up),
            bytes_down: r(&self.bytes_down),
            tcp_active: r(&self.tcp_active),
            udp_active: r(&self.udp_active),
            flows_opened: r(&self.flows_opened),
            flows_blocked: r(&self.flows_blocked),
            connect_failed: r(&self.connect_failed),
            dropped: r(&self.dropped),
        }
    }
}

fn bump(counter: &AtomicU64, by: u64) {
    counter.fetch_add(by, Ordering::Relaxed);
}

/// Controls a running forwarder. Dropping it stops the forwarder.
pub struct ForwarderHandle {
    inbox: Arc<Mutex<Vec<Vec<u8>>>>,
    waker: Arc<Waker>,
    stop: Arc<AtomicBool>,
    stats: Arc<Stats>,
    thread: Option<JoinHandle<()>>,
}

impl ForwarderHandle {
    /// Hands packets read from the tunnel to the forwarder.
    pub fn push_packets(&self, packets: impl IntoIterator<Item = Vec<u8>>) {
        {
            let mut inbox = self.inbox.lock().unwrap_or_else(|e| e.into_inner());
            inbox.extend(packets);
        }
        let _ = self.waker.wake();
    }

    pub fn stats(&self) -> StatsSnapshot {
        self.stats.snapshot()
    }

    /// Resets every open connection and waits for the thread to exit.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = self.waker.wake();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for ForwarderHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub fn spawn(
    host: Host,
    config: ForwarderConfig,
    sink: Arc<dyn EventSink>,
) -> io::Result<ForwarderHandle> {
    let poll = Poll::new()?;
    let waker = Arc::new(Waker::new(poll.registry(), WAKER)?);
    let inbox = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(Stats::default());

    let mut forwarder = Forwarder::new(
        host,
        config,
        sink,
        poll,
        inbox.clone(),
        stop.clone(),
        stats.clone(),
    );
    let thread = std::thread::Builder::new()
        .name("flynn-forwarder".into())
        .spawn(move || forwarder.run())?;
    Ok(ForwarderHandle {
        inbox,
        waker,
        stop,
        stats,
        thread: Some(thread),
    })
}

struct Forwarder {
    host: Host,
    config: ForwarderConfig,
    sink: Arc<dyn EventSink>,
    poll: Poll,
    inbox: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
    stats: Arc<Stats>,

    iface: Interface,
    device: TunDevice,
    sockets: SocketSet<'static>,
    names: DnsCache,
    pending: HashMap<FlowKey, PendingTcp>,
    tcp: HashMap<FlowKey, TcpFlow>,
    udp: HashMap<FlowKey, UdpFlow>,
    next_id: FlowId,
    epoch: Instant,
    scratch: Vec<u8>,
}

impl Forwarder {
    fn new(
        host: Host,
        config: ForwarderConfig,
        sink: Arc<dyn EventSink>,
        poll: Poll,
        inbox: Arc<Mutex<Vec<Vec<u8>>>>,
        stop: Arc<AtomicBool>,
        stats: Arc<Stats>,
    ) -> Self {
        let epoch = Instant::now();
        let mut device = TunDevice::new(config.mtu);
        let mut iface_config = Config::new(HardwareAddress::Ip);
        iface_config.random_seed = host.clock.now_unix_millis() as u64 ^ 0x9e37_79b9_7f4a_7c15;
        let mut iface = Interface::new(iface_config, &mut device, smoltcp::time::Instant::ZERO);
        // Any-IP: accept connections to every destination. The addresses
        // only anchor the default routes any-IP requires.
        let v4 = Ipv4Address::new(10, 111, 0, 254);
        let v6 = Ipv6Address::new(0xfd00, 0xf1, 0, 0, 0, 0, 0, 0xfe);
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(v4), 32));
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(v6), 128));
        });
        let _ = iface.routes_mut().add_default_ipv4_route(v4);
        let _ = iface.routes_mut().add_default_ipv6_route(v6);
        iface.set_any_ip(true);

        Self {
            names: DnsCache::new(config.dns_cache_size),
            host,
            config,
            sink,
            poll,
            inbox,
            stop,
            stats,
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
            pending: HashMap::new(),
            tcp: HashMap::new(),
            udp: HashMap::new(),
            next_id: 1,
            epoch,
            scratch: vec![0; 64 * 1024],
        }
    }

    fn now(&self) -> smoltcp::time::Instant {
        smoltcp::time::Instant::from_micros(self.epoch.elapsed().as_micros() as i64)
    }

    fn now_ms(&self) -> i64 {
        self.host.clock.now_unix_millis()
    }

    fn run(&mut self) {
        let mut events = Events::with_capacity(256);
        loop {
            let timeout = self
                .iface
                .poll_delay(self.now(), &self.sockets)
                .map(|d| Duration::from_micros(d.total_micros()))
                .map_or(Duration::from_secs(1), |d| d.min(Duration::from_secs(1)));
            if let Err(e) = self.poll.poll(&mut events, Some(timeout))
                && e.kind() != io::ErrorKind::Interrupted
            {
                break;
            }
            if self.stop.load(Ordering::Acquire) {
                break;
            }
            self.step();
        }
        self.shutdown();
    }

    /// One pass: take packets in, run the stack, move bytes, send packets out.
    fn step(&mut self) {
        let packets = std::mem::take(&mut *self.inbox.lock().unwrap_or_else(|e| e.into_inner()));
        bump(&self.stats.packets_in, packets.len() as u64);
        for packet in packets {
            self.ingest(packet);
        }
        let now = self.now();
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        self.service_pending();
        self.service_tcp();
        self.service_udp();
        // Send what the relay queued and any final FINs and RSTs.
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        self.reap();
        self.flush();
    }

    fn next_id(&mut self) -> FlowId {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn ingest(&mut self, packet: Vec<u8>) {
        let Ok(p) = ip::parse(&packet) else {
            bump(&self.stats.dropped, 1);
            return;
        };
        if p.later_fragment {
            bump(&self.stats.dropped, 1);
            return;
        }
        match p.protocol {
            ip::PROTO_TCP => {
                let Ok(t) = transport::parse_tcp(p.payload) else {
                    bump(&self.stats.dropped, 1);
                    return;
                };
                let key = FlowKey {
                    protocol: Transport::Tcp,
                    src: (p.src, t.src_port).into(),
                    dst: (p.dst, t.dst_port).into(),
                };
                let initial_syn = t.flags.is_initial_syn();
                if self.tcp.contains_key(&key) {
                    self.device.rx.push_back(packet);
                } else if self.pending.contains_key(&key) {
                    // A retransmitted SYN while the server connect is in flight.
                } else if initial_syn {
                    self.open_tcp(key, packet);
                } else {
                    // Unknown connection: smoltcp answers with a reset.
                    self.device.rx.push_back(packet);
                }
            }
            ip::PROTO_UDP => {
                let Ok(u) = transport::parse_udp(p.payload) else {
                    bump(&self.stats.dropped, 1);
                    return;
                };
                let key = FlowKey {
                    protocol: Transport::Udp,
                    src: (p.src, u.src_port).into(),
                    dst: (p.dst, u.dst_port).into(),
                };
                self.ingest_udp(key, u.payload);
            }
            _ => bump(&self.stats.dropped, 1),
        }
    }

    /// Names, attributes and decides a new flow, emitting `FlowOpened`.
    fn admit(&mut self, key: FlowKey) -> (FlowId, Verdict, Option<flynn_types::AppId>) {
        let id = self.next_id();
        let name = self.names.lookup(&key.dst.ip()).map(str::to_owned);
        let app = self.host.apps.resolve(&key);
        let verdict = self.config.policy.decide(&FlowMeta {
            key: &key,
            name: name.as_deref(),
            app: app.as_ref(),
        });
        bump(&self.stats.flows_opened, 1);
        self.sink.emit(Event::FlowOpened {
            id,
            at_ms: self.now_ms(),
            key,
            source: if name.is_some() {
                NameSource::Dns
            } else {
                NameSource::None
            },
            name,
            app: app.clone(),
            verdict,
        });
        (id, verdict, app)
    }

    fn close_event(&self, id: FlowId, bytes_up: u64, bytes_down: u64, reason: CloseReason) {
        self.sink.emit(Event::FlowClosed {
            id,
            at_ms: self.now_ms(),
            bytes_up,
            bytes_down,
            reason,
        });
    }

    fn open_tcp(&mut self, key: FlowKey, syn: Vec<u8>) {
        let (id, verdict, app) = self.admit(key);
        if verdict == Verdict::Block {
            bump(&self.stats.flows_blocked, 1);
            self.close_event(id, 0, 0, CloseReason::Blocked);
            self.device.rx.push_back(syn);
            return;
        }
        if self.tcp.len() + self.pending.len() >= self.config.max_tcp_flows {
            self.close_event(id, 0, 0, CloseReason::Capacity);
            self.device.rx.push_back(syn);
            return;
        }
        let target = self
            .config
            .redirects
            .get(&key.dst)
            .copied()
            .unwrap_or(key.dst);
        let stream = net::connect_tcp(target, &*self.host.protector).and_then(|mut stream| {
            self.poll.registry().register(
                &mut stream,
                Token(id as usize),
                Interest::READABLE | Interest::WRITABLE,
            )?;
            Ok(stream)
        });
        match stream {
            Ok(stream) => {
                self.pending.insert(
                    key,
                    PendingTcp {
                        id,
                        syn,
                        stream,
                        started: Instant::now(),
                        app,
                    },
                );
            }
            Err(_) => {
                bump(&self.stats.connect_failed, 1);
                self.close_event(id, 0, 0, CloseReason::ConnectFailed);
                self.device.rx.push_back(syn);
            }
        }
    }

    fn service_pending(&mut self) {
        let mut ready = Vec::new();
        for (key, p) in &self.pending {
            let outcome = match p.stream.take_error() {
                Ok(Some(_)) | Err(_) => Some(false),
                Ok(None) => match p.stream.peer_addr() {
                    Ok(_) => Some(true),
                    Err(e) if e.kind() == io::ErrorKind::NotConnected => {
                        (p.started.elapsed() > self.config.connect_timeout).then_some(false)
                    }
                    Err(_) => Some(false),
                },
            };
            if let Some(ok) = outcome {
                ready.push((*key, ok));
            }
        }
        for (key, ok) in ready {
            let Some(p) = self.pending.remove(&key) else {
                continue;
            };
            if !ok {
                bump(&self.stats.connect_failed, 1);
                self.close_event(p.id, 0, 0, CloseReason::ConnectFailed);
                self.device.rx.push_back(p.syn);
                continue;
            }
            let mut socket = TcpSocket::new(
                SocketBuffer::new(vec![0; self.config.tcp_recv_buffer]),
                SocketBuffer::new(vec![0; self.config.tcp_send_buffer]),
            );
            socket.set_nagle_enabled(false);
            let endpoint = IpListenEndpoint {
                addr: Some(key.dst.ip().into()),
                port: key.dst.port(),
            };
            if socket.listen(endpoint).is_err() {
                self.close_event(p.id, 0, 0, CloseReason::Reset);
                self.device.rx.push_back(p.syn);
                continue;
            }
            let handle = self.sockets.add(socket);
            // The held SYN now meets a listening socket.
            self.device.rx.push_back(p.syn);
            self.tcp.insert(
                key,
                TcpFlow {
                    id: p.id,
                    key,
                    handle,
                    stream: p.stream,
                    app: p.app,
                    created: Instant::now(),
                    established: false,
                    sniffing: true,
                    first_data: None,
                    remote_eof: false,
                    local_eof: false,
                    bytes_up: 0,
                    bytes_down: 0,
                    finished: None,
                },
            );
            bump(&self.stats.tcp_active, 1);
        }
    }

    fn service_tcp(&mut self) {
        let mut ctx = RelayCtx {
            policy: &*self.config.policy,
            sink: &*self.sink,
            scratch: &mut self.scratch,
            sni_wait: self.config.sni_wait,
            listen_timeout: self.config.connect_timeout,
        };
        for flow in self.tcp.values_mut() {
            let socket = self.sockets.get_mut::<TcpSocket>(flow.handle);
            let (up, down) = (flow.bytes_up, flow.bytes_down);
            flow.relay(socket, &mut ctx);
            bump(&self.stats.bytes_up, flow.bytes_up - up);
            bump(&self.stats.bytes_down, flow.bytes_down - down);
        }
    }

    fn ingest_udp(&mut self, key: FlowKey, payload: &[u8]) {
        if let Some(flow) = self.udp.get_mut(&key) {
            let before = flow.bytes_up;
            flow.send(payload);
            bump(&self.stats.bytes_up, flow.bytes_up - before);
            return;
        }
        let (id, verdict, _app) = self.admit(key);
        if verdict == Verdict::Block {
            bump(&self.stats.flows_blocked, 1);
            self.close_event(id, 0, 0, CloseReason::Blocked);
            return;
        }
        if self.udp.len() >= self.config.max_udp_flows {
            self.close_event(id, 0, 0, CloseReason::Capacity);
            return;
        }
        let target = self
            .config
            .redirects
            .get(&key.dst)
            .copied()
            .unwrap_or(key.dst);
        let socket = net::connect_udp(target, &*self.host.protector).and_then(|mut socket| {
            self.poll
                .registry()
                .register(&mut socket, Token(id as usize), Interest::READABLE)?;
            Ok(socket)
        });
        let socket = match socket {
            Ok(socket) => socket,
            Err(_) => {
                bump(&self.stats.connect_failed, 1);
                self.close_event(id, 0, 0, CloseReason::ConnectFailed);
                return;
            }
        };
        let mut flow = UdpFlow {
            id,
            key,
            socket,
            last_active: Instant::now(),
            is_dns: key.dst.port() == 53,
            answered: false,
            bytes_up: 0,
            bytes_down: 0,
            finished: None,
        };
        flow.send(payload);
        bump(&self.stats.bytes_up, flow.bytes_up);
        self.udp.insert(key, flow);
        bump(&self.stats.udp_active, 1);
    }

    fn service_udp(&mut self) {
        let now_ms = self.now_ms();
        let (udp_idle, dns_idle) = (self.config.udp_idle, self.config.dns_idle);
        for flow in self.udp.values_mut() {
            let before = flow.bytes_down;
            flow.receive(
                &mut self.scratch,
                &mut self.device.tx,
                &mut self.names,
                &*self.sink,
                now_ms,
            );
            bump(&self.stats.bytes_down, flow.bytes_down - before);
            let idle = flow.last_active.elapsed();
            if flow.finished.is_none() && (idle > udp_idle || (flow.answered && idle > dns_idle)) {
                flow.finished = Some(CloseReason::Idle);
            }
        }
    }

    /// Removes finished flows once their last packets have been sent.
    fn reap(&mut self) {
        let done: Vec<FlowKey> = self
            .tcp
            .iter()
            .filter(|(_, f)| f.finished.is_some())
            .map(|(k, _)| *k)
            .collect();
        for key in done {
            if let Some(flow) = self.tcp.remove(&key) {
                self.sockets.remove(flow.handle);
                let _ = self.poll.registry().deregister(&mut { flow.stream });
                self.stats.tcp_active.fetch_sub(1, Ordering::Relaxed);
                self.close_event(
                    flow.id,
                    flow.bytes_up,
                    flow.bytes_down,
                    flow.finished.unwrap_or(CloseReason::Normal),
                );
            }
        }
        let done: Vec<FlowKey> = self
            .udp
            .iter()
            .filter(|(_, f)| f.finished.is_some())
            .map(|(k, _)| *k)
            .collect();
        for key in done {
            if let Some(flow) = self.udp.remove(&key) {
                self.stats.udp_active.fetch_sub(1, Ordering::Relaxed);
                self.close_event(
                    flow.id,
                    flow.bytes_up,
                    flow.bytes_down,
                    flow.finished.unwrap_or(CloseReason::Normal),
                );
            }
        }
    }

    fn flush(&mut self) {
        if self.device.tx.is_empty() {
            return;
        }
        let batch = std::mem::take(&mut self.device.tx);
        bump(&self.stats.packets_out, batch.len() as u64);
        let _ = self.host.packets.write_packets(batch);
    }

    fn shutdown(&mut self) {
        for p in std::mem::take(&mut self.pending).into_values() {
            self.close_event(p.id, 0, 0, CloseReason::Shutdown);
        }
        for flow in self.tcp.values_mut() {
            self.sockets.get_mut::<TcpSocket>(flow.handle).abort();
            flow.finished.get_or_insert(CloseReason::Shutdown);
        }
        for flow in self.udp.values_mut() {
            flow.finished.get_or_insert(CloseReason::Shutdown);
        }
        let now = self.now();
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        self.reap();
        self.flush();
    }
}
