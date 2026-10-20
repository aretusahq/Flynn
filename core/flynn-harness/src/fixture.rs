//! Synthetic traffic for the replay fixtures. Deterministic, and free of
//! anyone's real traffic, so the capture can be committed.

use std::net::SocketAddr;

use flynn_proto::build::{self, DnsRecord};
use flynn_proto::dns::{TYPE_A, TYPE_AAAA};
use flynn_proto::transport::TcpFlags;

use crate::pcap::Packet;

const SYN: u8 = TcpFlags::SYN;
const ACK: u8 = TcpFlags::ACK;
const FIN: u8 = TcpFlags::FIN;

struct Script {
    packets: Vec<Packet>,
    at_ms: i64,
}

impl Script {
    fn push(&mut self, ip: Vec<u8>) {
        self.at_ms += 10;
        self.packets.push(Packet {
            at_ms: self.at_ms,
            ip,
        });
    }

    fn dns(
        &mut self,
        client: &str,
        resolver: &str,
        id: u16,
        name: &str,
        qtype: u16,
        records: &[DnsRecord<'_>],
    ) {
        let (c, r) = (addr(client), addr(resolver));
        self.push(build::udp_packet(c, r, &build::dns_query(id, name, qtype)));
        self.push(build::udp_packet(
            r,
            c,
            &build::dns_response(id, name, records),
        ));
    }

    /// A whole TCP connection: handshake, client data in MSS-sized segments,
    /// server data, and a FIN in each direction.
    fn tcp(&mut self, client: &str, server: &str, up: &[u8], down: &[u8]) {
        let (c, s) = (addr(client), addr(server));
        let (mut cseq, mut sseq) = (1000u32, 5000u32);
        self.push(build::tcp_packet(c, s, cseq, 0, SYN, &[]));
        self.push(build::tcp_packet(s, c, sseq, cseq + 1, SYN | ACK, &[]));
        cseq += 1;
        sseq += 1;
        self.push(build::tcp_packet(c, s, cseq, sseq, ACK, &[]));
        for chunk in up.chunks(1400) {
            self.push(build::tcp_packet(c, s, cseq, sseq, ACK, chunk));
            cseq += chunk.len() as u32;
        }
        for chunk in down.chunks(1400) {
            self.push(build::tcp_packet(s, c, sseq, cseq, ACK, chunk));
            sseq += chunk.len() as u32;
        }
        self.push(build::tcp_packet(c, s, cseq, sseq, FIN | ACK, &[]));
        self.push(build::tcp_packet(s, c, sseq, cseq + 1, FIN | ACK, &[]));
        self.push(build::tcp_packet(c, s, cseq + 1, sseq + 1, ACK, &[]));
    }
}

fn addr(s: &str) -> SocketAddr {
    s.parse().expect("fixture address")
}

/// The basic fixture: DNS-named and SNI-named TLS, a two-segment
/// ClientHello, a tracker to block, plain HTTP to a bare address, QUIC,
/// IPv6, and two packets the tracker must skip.
pub fn basic() -> Vec<Packet> {
    let mut s = Script {
        packets: Vec::new(),
        at_ms: 1_760_000_000_000,
    };

    s.dns(
        "10.0.0.2:50001",
        "10.0.0.1:53",
        1,
        "www.example.com",
        TYPE_A,
        &[DnsRecord::A([93, 184, 216, 34])],
    );
    // A post-quantum-sized ClientHello spans two segments.
    s.tcp(
        "10.0.0.2:50100",
        "93.184.216.34:443",
        &build::client_hello(Some("www.example.com"), 1700),
        &[7; 3000],
    );

    s.dns(
        "10.0.0.2:50002",
        "10.0.0.1:53",
        2,
        "ads.tracker.test",
        TYPE_A,
        &[
            DnsRecord::Cname("edge.cdn.test"),
            DnsRecord::A([203, 0, 113, 7]),
        ],
    );
    s.tcp(
        "10.0.0.2:50101",
        "203.0.113.7:443",
        &build::client_hello(Some("ads.tracker.test"), 0),
        &[1; 200],
    );

    // No DNS seen and no TLS: an unknown destination.
    s.tcp(
        "10.0.0.2:50102",
        "198.51.100.20:80",
        b"GET / HTTP/1.1\r\nHost: 198.51.100.20\r\n\r\n",
        &[2; 512],
    );

    // QUIC to the DNS-named address.
    let (c, q) = (addr("10.0.0.2:60000"), addr("93.184.216.34:443"));
    let mut initial = vec![0xc3, 0, 0, 0, 1, 8];
    initial.resize(1200, 0);
    s.push(build::udp_packet(c, q, &initial));
    s.push(build::udp_packet(q, c, &[0x40; 900]));

    // QUIC with real Initial protection, the ClientHello split over two
    // datagrams: named from the Initials, and one of them blocked.
    for (port, server, name) in [
        (60001, "203.0.113.50:443", "video.example.net"),
        (60002, "203.0.113.7:443", "beacon.tracker.test"),
    ] {
        let (c, q) = (addr(&format!("10.0.0.2:{port}")), addr(server));
        let hello = build::client_hello(Some(name), 1500);
        for d in build::quic_initials(
            flynn_proto::quic::VERSION_1,
            &[port as u8; 8],
            &hello[5..],
            2,
        ) {
            s.push(build::udp_packet(c, q, &d));
        }
        s.push(build::udp_packet(q, c, &[0x40; 300]));
    }

    // IPv6: AAAA lookup, then a connection named by SNI that differs from DNS.
    s.dns(
        "[fd00::2]:50003",
        "[fd00::1]:53",
        3,
        "v6.example.org",
        TYPE_AAAA,
        &[DnsRecord::Aaaa(
            "2001:db8::443".parse().expect("fixture address"),
        )],
    );
    s.tcp(
        "[fd00::2]:50104",
        "[2001:db8::443]:443",
        &build::client_hello(Some("api.example.org"), 0),
        &[3; 100],
    );

    // Skipped: ICMP echo, and a later IPv4 fragment.
    let mut icmp = build::udp_packet(addr("10.0.0.2:1"), addr("10.0.0.1:1"), &[0; 8]);
    icmp[9] = 1;
    s.push(icmp);
    let mut frag = build::udp_packet(addr("10.0.0.2:2"), addr("10.0.0.1:2"), &[0; 8]);
    frag[6..8].copy_from_slice(&0x0010u16.to_be_bytes());
    s.push(frag);

    s.packets
}
