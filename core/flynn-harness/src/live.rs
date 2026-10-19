//! `live`: route the Mac's traffic through the forwarder over a utun
//! interface, printing throughput, flows and memory as it runs.

use std::io;
use std::net::IpAddr;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use flynn_dataplane::forwarder::{self, ForwarderConfig};
use flynn_dataplane::{
    AppResolver, Clock, CloseReason, Event, EventSink, FlowKey, Host, HostError, Notifier,
    PacketIo, Paths, Policy, SocketProtector, StatsSnapshot,
};
use flynn_rules::Verdict;
use flynn_types::AppId;

use crate::utun::Utun;

pub struct LiveOptions {
    pub routes: Vec<String>,
    pub all: bool,
    pub interface: Option<String>,
    pub print_events: bool,
    pub stats_every: Duration,
    pub policy: Arc<dyn Policy>,
    pub recv_buffer: usize,
    pub send_buffer: usize,
    /// Also write events to a spool in this directory.
    pub spool: Option<std::path::PathBuf>,
}

const TUN_V4: &str = "10.111.0.1";
const TUN_V4_PEER: &str = "10.111.0.2";
const TUN_V6: &str = "fd00:f1::1";

pub fn run(opts: LiveOptions) -> io::Result<()> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::other(
            "live mode creates an interface and routes: run it with sudo",
        ));
    }
    let physical = match &opts.interface {
        Some(name) => name.clone(),
        None => default_interface()?,
    };
    let ifindex = if_index(&physical)?;
    let utun = Arc::new(Utun::open()?);
    println!(
        "utun: {}  outbound via: {physical} (index {ifindex})",
        utun.name
    );

    sh(
        "ifconfig",
        &[&utun.name, "inet", TUN_V4, TUN_V4_PEER, "mtu", "1500", "up"],
    )?;
    sh(
        "ifconfig",
        &[&utun.name, "inet6", TUN_V6, "prefixlen", "128"],
    )?;
    let mut routes = opts.routes.clone();
    if opts.all {
        routes.extend(["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"].map(String::from));
    }
    if routes.is_empty() {
        println!("no routes given: nothing will reach the tunnel. Use --route CIDR or --all.");
    }
    for cidr in &routes {
        let family = if cidr.contains(':') {
            "-inet6"
        } else {
            "-inet"
        };
        sh(
            "route",
            &[
                "-q",
                "-n",
                "add",
                family,
                "-net",
                cidr,
                "-interface",
                &utun.name,
            ],
        )?;
        println!("route: {cidr} -> {}", utun.name);
    }

    let stopping = Arc::new(AtomicBool::new(false));
    {
        let stopping = stopping.clone();
        ctrlc::set_handler(move || stopping.store(true, Ordering::SeqCst))
            .map_err(io::Error::other)?;
    }

    let sink = Arc::new(Printer {
        print: opts.print_events,
        totals: Mutex::new(Totals::default()),
    });
    let host = Host {
        packets: Arc::new(UtunWriter(utun.clone())),
        protector: Arc::new(BoundInterface(ifindex)),
        apps: Arc::new(NoApps),
        clock: Arc::new(WallClock),
        paths: Arc::new(TmpPaths),
        notifier: Arc::new(StdoutNotifier),
    };
    let mut config = ForwarderConfig::new(opts.policy);
    config.tcp_recv_buffer = opts.recv_buffer;
    config.tcp_send_buffer = opts.send_buffer;
    println!(
        "tcp buffers: recv {} KiB, send {} KiB per connection",
        opts.recv_buffer / 1024,
        opts.send_buffer / 1024
    );
    let spool = match &opts.spool {
        Some(dir) => {
            println!("spool: {}", dir.display());
            Some(Arc::new(flynn_dataplane::spool::SpoolSink::open(dir)?))
        }
        None => None,
    };
    let tee: Arc<dyn EventSink> = Arc::new(Tee {
        printer: sink.clone(),
        spool: spool.clone(),
    });
    let fwd = Arc::new(forwarder::spawn(host, config, tee)?);

    // Reader: tunnel -> forwarder. Blocks in read(2) until the process exits.
    {
        let utun = utun.clone();
        let fwd = fwd.clone();
        std::thread::Builder::new()
            .name("utun-reader".into())
            .spawn(move || {
                let mut buf = vec![0u8; 65536];
                loop {
                    match utun.read_packet(&mut buf) {
                        Ok(0) => continue,
                        Ok(n) => fwd.push_packets([buf[..n].to_vec()]),
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
            })?;
    }

    println!("running; Ctrl-C to stop and print the summary\n");
    let start = Instant::now();
    let mut last = (Instant::now(), StatsSnapshot::default());
    let mut peak_rate = (0f64, 0f64);
    while !stopping.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(200));
        if last.0.elapsed() >= opts.stats_every {
            let now = fwd.stats();
            let secs = last.0.elapsed().as_secs_f64();
            let up = (now.bytes_up - last.1.bytes_up) as f64 / secs;
            let down = (now.bytes_down - last.1.bytes_down) as f64 / secs;
            peak_rate = (peak_rate.0.max(up), peak_rate.1.max(down));
            let mem = flynn_dataplane::mem::sample();
            println!(
                "[{:>6.0}s] up {:>8} down {:>8}  tcp {:>3} udp {:>3}  opened {} blocked {} failed {} dropped {}  footprint {} (peak {})  cpu {:.1}s",
                start.elapsed().as_secs_f64(),
                rate(up),
                rate(down),
                now.tcp_active,
                now.udp_active,
                now.flows_opened,
                now.flows_blocked,
                now.connect_failed,
                now.dropped,
                mib(mem.footprint),
                mib(mem.peak_footprint),
                (mem.cpu_ms as f64 / 1000.0),
            );
            last = (Instant::now(), now);
        }
    }

    let stats = fwd.stats();
    let mem = flynn_dataplane::mem::sample();
    let elapsed = start.elapsed().as_secs_f64();
    if let Ok(fwd) = Arc::try_unwrap(fwd) {
        fwd.stop();
    }
    let totals = sink.totals.lock().map(|t| t.clone()).unwrap_or_default();
    println!("\n--- summary (paste into docs/spike-results.md) ---");
    println!("duration: {elapsed:.0} s");
    println!(
        "relayed: up {} / down {}",
        bytes(stats.bytes_up),
        bytes(stats.bytes_down)
    );
    println!(
        "average: up {} / down {}",
        rate(stats.bytes_up as f64 / elapsed),
        rate(stats.bytes_down as f64 / elapsed)
    );
    println!(
        "peak ({}s window): up {} / down {}",
        opts.stats_every.as_secs(),
        rate(peak_rate.0),
        rate(peak_rate.1)
    );
    println!(
        "flows: {} opened, {} blocked, {} connect failures; closed normal {} / reset {} / idle {}",
        stats.flows_opened,
        stats.flows_blocked,
        stats.connect_failed,
        totals.normal,
        totals.reset,
        totals.idle
    );
    println!(
        "named: {} by DNS, {} by SNI, {} unnamed",
        totals.named_dns, totals.named_sni, totals.unnamed
    );
    println!(
        "packets: {} in / {} out, {} dropped (not TCP/UDP or fragments)",
        stats.packets_in, stats.packets_out, stats.dropped
    );
    println!(
        "memory: footprint {} now, {} peak (whole harness process)",
        mib(mem.footprint),
        mib(mem.peak_footprint)
    );
    println!(
        "cpu: {:.1} s user+system ({:.1}% of one core)",
        (mem.cpu_ms as f64 / 1000.0),
        100.0 * (mem.cpu_ms as f64 / 1000.0) / elapsed
    );
    // Dropping the utun descriptor at exit removes the interface and routes.
    Ok(())
}

fn sh(cmd: &str, args: &[&str]) -> io::Result<()> {
    let status = Command::new(cmd).args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{cmd} {} failed: {status}",
            args.join(" ")
        )))
    }
}

/// The interface carrying the default route, e.g. en0.
fn default_interface() -> io::Result<String> {
    let out = Command::new("route")
        .args(["-n", "get", "default"])
        .output()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("interface:")
                .map(|s| s.trim().to_string())
        })
        .ok_or_else(|| io::Error::other("no default route; pass --interface"))
}

fn if_index(name: &str) -> io::Result<u32> {
    let c = std::ffi::CString::new(name).map_err(io::Error::other)?;
    // SAFETY: `c` is a valid NUL-terminated string.
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        Err(io::Error::other(format!("no interface {name}")))
    } else {
        Ok(idx)
    }
}

fn rate(bytes_per_sec: f64) -> String {
    format!("{:.2} Mb/s", bytes_per_sec * 8.0 / 1e6)
}

fn bytes(n: u64) -> String {
    format!("{:.1} MB", n as f64 / 1e6)
}

fn mib(n: u64) -> String {
    format!("{:.1} MiB", n as f64 / (1024.0 * 1024.0))
}

// ----- Host for the Mac -----------------------------------------------------

struct UtunWriter(Arc<Utun>);

impl PacketIo for UtunWriter {
    fn write_packets(&self, packets: Vec<Vec<u8>>) -> Result<(), HostError> {
        for p in &packets {
            self.0
                .write_packet(p)
                .map_err(|e| HostError::Rejected(e.to_string()))?;
        }
        Ok(())
    }
}

/// Pins each outbound socket to the physical interface with IP_BOUND_IF, the
/// macOS counterpart of Android's VpnService.protect(): without it the
/// forwarder's own connections would follow the routes back into the utun.
struct BoundInterface(u32);

impl SocketProtector for BoundInterface {
    fn protect(&self, fd: i32) -> bool {
        // SAFETY: sockaddr_storage is plain data; getsockname reports the family.
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        if unsafe {
            libc::getsockname(
                fd,
                (&mut storage as *mut libc::sockaddr_storage).cast(),
                &mut len,
            )
        } < 0
        {
            return false;
        }
        let (level, option) = match i32::from(storage.ss_family) {
            libc::AF_INET6 => (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF),
            _ => (libc::IPPROTO_IP, libc::IP_BOUND_IF),
        };
        let index = self.0 as libc::c_int;
        // SAFETY: the option value is a c_int of the stated size.
        unsafe {
            libc::setsockopt(
                fd,
                level,
                option,
                (&index as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) == 0
        }
    }
}

struct NoApps;
impl AppResolver for NoApps {
    fn resolve(&self, _flow: &FlowKey) -> Option<AppId> {
        None
    }
}

struct WallClock;
impl Clock for WallClock {
    fn now_unix_millis(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as i64)
    }
}

struct TmpPaths;
impl Paths for TmpPaths {
    fn spool_dir(&self) -> std::path::PathBuf {
        std::env::temp_dir().join("flynn-harness-spool")
    }
    fn rule_snapshot(&self) -> std::path::PathBuf {
        std::env::temp_dir().join("flynn-harness-rules.snapshot")
    }
}

struct StdoutNotifier;
impl Notifier for StdoutNotifier {
    fn notify(&self, title: &str, body: &str) {
        println!("notify: {title}: {body}");
    }
}

#[derive(Default, Clone)]
struct Totals {
    normal: u64,
    reset: u64,
    idle: u64,
    named_dns: u64,
    named_sni: u64,
    unnamed: u64,
}

struct Printer {
    print: bool,
    totals: Mutex<Totals>,
}

impl EventSink for Printer {
    fn emit(&self, event: Event) {
        if let Ok(mut t) = self.totals.lock() {
            match &event {
                Event::FlowClosed {
                    reason: CloseReason::Normal,
                    ..
                } => t.normal += 1,
                Event::FlowClosed {
                    reason: CloseReason::Reset,
                    ..
                } => t.reset += 1,
                Event::FlowClosed {
                    reason: CloseReason::Idle,
                    ..
                } => t.idle += 1,
                Event::FlowOpened { name: Some(_), .. } => t.named_dns += 1,
                Event::FlowOpened { name: None, .. } => t.unnamed += 1,
                Event::FlowNamed { .. } => t.named_sni += 1,
                _ => {}
            }
        }
        if !self.print {
            return;
        }
        match event {
            Event::FlowOpened {
                id,
                key,
                name,
                verdict,
                ..
            } => {
                let v = if verdict == Verdict::Block {
                    "BLOCK"
                } else {
                    "allow"
                };
                println!(
                    "open  #{id} {:?} {} -> {} {} [{v}]",
                    key.protocol,
                    key.src,
                    key.dst,
                    name.as_deref().unwrap_or("-")
                );
            }
            Event::FlowNamed { id, name, .. } => println!("name  #{id} {name} (sni)"),
            Event::FlowClosed {
                id,
                bytes_up,
                bytes_down,
                reason,
                ..
            } => {
                println!(
                    "close #{id} up {bytes_up} B down {bytes_down} B ({})",
                    reason.as_str()
                );
            }
            Event::DnsAnswer { name, addrs, .. } => {
                let addrs: Vec<String> = addrs.iter().map(IpAddr::to_string).collect();
                println!("dns   {name} = {}", addrs.join(", "));
            }
            // The periodic stats line already shows memory and counters.
            Event::Sample { .. } => {}
        }
    }
}

/// Sends each event to the printer and, when enabled, the spool.
struct Tee {
    printer: Arc<Printer>,
    spool: Option<Arc<flynn_dataplane::spool::SpoolSink>>,
}

impl EventSink for Tee {
    fn emit(&self, event: Event) {
        if let Some(spool) = &self.spool {
            spool.emit(event.clone());
        }
        self.printer.emit(event);
    }

    fn tick(&self) {
        if let Some(spool) = &self.spool {
            spool.tick();
        }
    }
}
