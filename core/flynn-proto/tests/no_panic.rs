//! Every parser must reject arbitrary bytes without panicking. These run on
//! every check; the cargo-fuzz targets in core/fuzz go deeper when a nightly
//! toolchain is available.

use flynn_proto::{build, dns, ip, quic, tls, transport};
use proptest::prelude::*;

fn parse_all(data: &[u8]) {
    if let Ok(p) = ip::parse(data) {
        let _ = transport::parse_tcp(p.payload);
        let _ = transport::parse_udp(p.payload);
    }
    let _ = transport::parse_tcp(data);
    let _ = transport::parse_udp(data);
    let _ = dns::parse(data);
    let _ = tls::client_hello_sni(data);
    let _ = quic::initial_version(data);
    let _ = quic::InitialSniffer::new().feed(data);
    let _ = tls::handshake_sni(data);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn random_bytes(data in proptest::collection::vec(any::<u8>(), 0..1600)) {
        parse_all(&data);
    }

    /// Mutating valid messages reaches deeper branches than random bytes.
    #[test]
    fn mutated_dns(flips in proptest::collection::vec((0usize..256, any::<u8>()), 1..8)) {
        let mut m = build::dns_response(1, "www.example.com", &[
            build::DnsRecord::Cname("cdn.example.net"),
            build::DnsRecord::A([1, 2, 3, 4]),
        ]);
        for (at, b) in flips {
            let i = at % m.len();
            m[i] = b;
        }
        let _ = dns::parse(&m);
    }

    #[test]
    fn mutated_client_hello(flips in proptest::collection::vec((0usize..512, any::<u8>()), 1..8), cut in 0usize..600) {
        let mut h = build::client_hello(Some("api.example.com"), 64);
        for (at, b) in flips {
            let i = at % h.len();
            h[i] = b;
        }
        let end = h.len().saturating_sub(cut % h.len());
        let _ = tls::client_hello_sni(&h[..end]);
    }

    /// Flipped bytes in a real Initial: header parsing and frame walking
    /// must survive whatever decrypts, and authentication rejects the rest.
    #[test]
    fn mutated_quic_initial(flips in proptest::collection::vec((0usize..1200, any::<u8>()), 1..6), cut in 0usize..1200) {
        let mut d = include_bytes!("../../fixtures/quic/apple-initial-0.bin").to_vec();
        for (at, b) in flips {
            let i = at % d.len();
            d[i] = b;
        }
        let end = d.len() - cut % d.len();
        let _ = quic::InitialSniffer::new().feed(&d[..end]);
    }

    #[test]
    fn mutated_ip(flips in proptest::collection::vec((0usize..64, any::<u8>()), 1..6)) {
        let mut p = build::udp_packet("[fd00::2]:5000".parse().unwrap(), "[2606:4700::1111]:53".parse().unwrap(), b"0123456789");
        for (at, b) in flips {
            let i = at % p.len();
            p[i] = b;
        }
        parse_all(&p);
    }
}
