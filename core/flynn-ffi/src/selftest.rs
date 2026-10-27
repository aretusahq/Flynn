//! An on-device check of the core, for builds that cannot run the tunnel
//! (a free Apple team has no Network Extension). It exercises the parts that
//! can differ on a real device: the crypto, the parsers, file writes, the
//! memory sampler and the forwarder's sockets and threads.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use flynn_dataplane::spool::{self, SpoolWriter};
use flynn_dataplane::{
    self as dp, CloseReason, Event, FlowKey, ForwarderConfig, NameSource, NullSink, RulesPolicy,
};
use flynn_proto::{build, dns, ip, quic, tls, transport};
use flynn_types::AppId;

#[derive(Debug, Clone, uniffi::Record)]
pub struct SelfTestEntry {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

/// Runs every check and reports each result. `scratch_dir` must be writable.
#[uniffi::export]
pub fn core_self_test(scratch_dir: String) -> Vec<SelfTestEntry> {
    let scratch = PathBuf::from(scratch_dir);
    vec![
        entry(
            "QUIC Initial keys match the RFC 9001 test vector",
            quic_keys(),
        ),
        entry(
            "Server name read from encrypted QUIC Initials",
            quic_names(),
        ),
        entry("TLS ClientHello and DNS parsing", parse_tls_dns()),
        entry(
            "Rules decide by precedence; the snapshot round-trips",
            rules_check(),
        ),
        entry(
            "Event spool writes and reads back",
            spool_round_trip(&scratch),
        ),
        entry("Memory sampler reports this process", memory()),
        entry("Forwarder relays UDP over loopback", forwarder_udp()),
    ]
}

fn entry(name: &str, result: Result<String, String>) -> SelfTestEntry {
    let (passed, detail) = match result {
        Ok(detail) => (true, detail),
        Err(detail) => (false, detail),
    };
    SelfTestEntry {
        name: name.to_string(),
        passed,
        detail,
    }
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn io(e: std::io::Error) -> String {
    e.to_string()
}

fn quic_keys() -> Result<String, String> {
    let keys = quic::client_initial_keys(quic::VERSION_1, &hex("8394c8f03e515708"))
        .ok_or("no keys derived")?;
    if keys.key.to_vec() != hex("1f369613dd76d5467730efcbe3b1a22d") {
        return Err("packet key differs".into());
    }
    if keys.iv.to_vec() != hex("fa044b2f42a3fd3b46fb255c") {
        return Err("IV differs".into());
    }
    if keys.hp.to_vec() != hex("9f50449e04a0e810283a1e9933adedd2") {
        return Err("header-protection key differs".into());
    }
    let sample: [u8; 16] = hex("d1b1c98dd7689fb8ec11d242b123dc9b")
        .try_into()
        .map_err(|_| "bad sample")?;
    if quic::header_mask(&keys.hp, &sample)[..5] != hex("437b9aec36")[..] {
        return Err("header mask differs".into());
    }
    Ok("key, IV, header-protection key and mask all match".into())
}

fn quic_names() -> Result<String, String> {
    let hello = build::client_hello(Some("selftest.example.org"), 1500);
    for version in [quic::VERSION_1, quic::VERSION_2] {
        let datagrams = build::quic_initials(version, &[7; 8], &hello[5..], 3);
        let mut sniffer = quic::InitialSniffer::new();
        let mut last = quic::QuicSni::Failed;
        for d in &datagrams {
            last = sniffer.feed(d);
        }
        match last {
            quic::QuicSni::Found(name) if name == "selftest.example.org" => {}
            other => return Err(format!("QUIC {version:#x}: {other:?}")),
        }
    }
    Ok("v1 and v2, ClientHello split over 3 datagrams (AES-GCM and HKDF)".into())
}

fn parse_tls_dns() -> Result<String, String> {
    let hello = build::client_hello(Some("a.example.com"), 64);
    match tls::client_hello_sni(&hello) {
        tls::Sni::Found("a.example.com") => {}
        other => return Err(format!("TLS: {other:?}")),
    }
    let response = build::dns_response(
        9,
        "www.example.com",
        &[
            build::DnsRecord::Cname("cdn.example.net"),
            build::DnsRecord::A([93, 184, 216, 34]),
        ],
    );
    let message = dns::parse(&response).map_err(|e| format!("DNS: {e:?}"))?;
    let want = dns::AnswerData::Address(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
    if !message.answers.iter().any(|a| a.data == want) {
        return Err(format!("DNS answers: {:?}", message.answers));
    }
    Ok("server name and a CNAME chain decoded".into())
}

fn rules_check() -> Result<String, String> {
    use flynn_rules::{Decision, NameState, Query, Reason, snapshot, text};
    let config =
        text::parse("mode block-all\nallow subdomains example.com\nblock domain bad.example.com\n")
            .map_err(|e| e.to_string())?;
    let bytes = snapshot::encode(&config, 4).map_err(|e| e.to_string())?;
    let rules = snapshot::decode(&bytes)
        .map_err(|e| e.to_string())?
        .compile()
        .map_err(|e| e.to_string())?;
    let ask = |name: NameState<'_>, port: u16| {
        rules.decide(&Query {
            transport: flynn_types::Transport::Tcp,
            dst: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            port,
            name,
            app: None,
        })
    };
    let expect = |got: Decision, want: Decision, what: &str| {
        if got == want {
            Ok(())
        } else {
            Err(format!("{what}: got {got:?}, wanted {want:?}"))
        }
    };
    expect(
        ask(NameState::Known("www.example.com"), 443),
        Decision::Allow(Reason::Rule { id: 1 }),
        "an allowed subdomain",
    )?;
    expect(
        ask(NameState::Known("bad.example.com"), 443),
        Decision::Block(Reason::Rule { id: 2 }),
        "the exact block beats the wildcard allow",
    )?;
    expect(
        ask(NameState::Known("other.test"), 443),
        Decision::Block(Reason::ModeDefault),
        "block-all's default",
    )?;
    expect(
        ask(NameState::Known("time.apple.com"), 443),
        Decision::Allow(Reason::Essential),
        "an essential name",
    )?;
    expect(
        ask(NameState::Pending, 443),
        Decision::Wait,
        "a name that could matter",
    )?;
    Ok("5 decisions as documented; snapshot encoded, decoded and compiled".into())
}

fn spool_round_trip(scratch: &Path) -> Result<String, String> {
    let dir = scratch.join(format!("spool-selftest-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let events = vec![
        Event::FlowNamed {
            id: 1,
            name: "x.example".into(),
            source: NameSource::Sni,
        },
        Event::FlowClosed {
            id: 1,
            at_ms: 5,
            bytes_up: 10,
            bytes_down: 20,
            reason: CloseReason::Normal,
        },
    ];
    {
        let mut writer = SpoolWriter::open(&dir, 1 << 20, 4).map_err(io)?;
        for e in &events {
            writer.append(e).map_err(io)?;
        }
        writer.flush().map_err(io)?;
    }
    let back = spool::tail(&dir, 10).map_err(io)?;
    let _ = std::fs::remove_dir_all(&dir);
    if back == events {
        Ok(format!(
            "{} events written, read back and compared",
            events.len()
        ))
    } else {
        Err(format!("read back {back:?}"))
    }
}

fn memory() -> Result<String, String> {
    let m = dp::mem::sample();
    if m.footprint == 0 {
        return Err("footprint is 0: the task_info call failed".into());
    }
    let mib = |b: u64| b as f64 / (1024.0 * 1024.0);
    Ok(format!(
        "footprint {:.1} MiB, peak {:.1} MiB, {} ms of CPU",
        mib(m.footprint),
        mib(m.peak_footprint),
        m.cpu_ms
    ))
}

/// What the forwarder needs from a host, kept in memory.
#[derive(Default)]
struct Local {
    to_app: Mutex<Vec<Vec<u8>>>,
}

impl dp::PacketIo for Local {
    fn write_packets(&self, packets: Vec<Vec<u8>>) -> Result<(), dp::HostError> {
        self.to_app
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend(packets);
        Ok(())
    }
}
impl dp::SocketProtector for Local {
    fn protect(&self, _fd: i32) -> bool {
        true
    }
}
impl dp::AppResolver for Local {
    fn resolve(&self, _flow: &FlowKey) -> Option<AppId> {
        None
    }
}
impl dp::Clock for Local {
    fn now_unix_millis(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as i64)
    }
}
impl dp::Paths for Local {
    fn spool_dir(&self) -> PathBuf {
        std::env::temp_dir()
    }
    fn rule_snapshot(&self) -> PathBuf {
        std::env::temp_dir().join("rules.snapshot")
    }
}
impl dp::Notifier for Local {
    fn notify(&self, _title: &str, _body: &str) {}
}

fn forwarder_udp() -> Result<String, String> {
    let server = UdpSocket::bind("127.0.0.1:0").map_err(io)?;
    server
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(io)?;
    let target = server.local_addr().map_err(io)?;

    let local = Arc::new(Local::default());
    let host = dp::Host {
        packets: local.clone(),
        protector: local.clone(),
        apps: local.clone(),
        clock: local.clone(),
        paths: local.clone(),
        notifier: local.clone(),
    };
    let config = ForwarderConfig::new(Arc::new(RulesPolicy::allow_all()));
    let handle = dp::forwarder::spawn(host, config, Arc::new(NullSink)).map_err(io)?;

    let app: SocketAddr = "10.0.0.2:5000".parse().map_err(|_| "bad address")?;
    handle.push_packets([build::udp_packet(app, target, b"flynn self-test")]);
    let mut buf = [0u8; 64];
    let (n, peer) = server
        .recv_from(&mut buf)
        .map_err(|e| format!("the datagram never reached the server: {e}"))?;
    if &buf[..n] != b"flynn self-test" {
        return Err("the server received different bytes".into());
    }
    server.send_to(b"reply", peer).map_err(io)?;

    let deadline = Instant::now() + Duration::from_secs(3);
    let reply = loop {
        let packet = local
            .to_app
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .first()
            .cloned();
        if let Some(p) = packet {
            break p;
        }
        if Instant::now() > deadline {
            return Err("no reply packet came back to the app side".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let parsed = ip::parse(&reply).map_err(|e| format!("reply: {e:?}"))?;
    let udp = transport::parse_udp(parsed.payload).map_err(|e| format!("reply: {e:?}"))?;
    if parsed.dst != app.ip() || udp.payload != b"reply" {
        return Err("the reply packet was not addressed back to the app".into());
    }
    handle.stop();
    Ok("a datagram out through the forwarder, and the reply back".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_check_passes_on_the_host() {
        let dir = std::env::temp_dir().join(format!("flynn-selftest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let results = core_self_test(dir.to_string_lossy().into_owned());
        let _ = std::fs::remove_dir_all(&dir);
        let failed: Vec<_> = results.iter().filter(|r| !r.passed).collect();
        assert!(failed.is_empty(), "failed: {failed:?}");
        assert_eq!(results.len(), 7);
    }
}
