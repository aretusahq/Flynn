//! Packet builders: UDP replies from the relay, and synthetic traffic for
//! tests and fixtures. Every packet gets valid checksums.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use crate::ip::{PROTO_TCP, PROTO_UDP};

/// An IPv4 or IPv6 packet carrying one UDP datagram.
///
/// Panics if `src` and `dst` are different IP versions.
pub fn udp_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut udp = Vec::with_capacity(8 + payload.len());
    udp.extend_from_slice(&src.port().to_be_bytes());
    udp.extend_from_slice(&dst.port().to_be_bytes());
    udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);
    let sum = transport_checksum(src.ip(), dst.ip(), PROTO_UDP, &udp);
    // A computed zero is sent as all ones (RFC 768).
    let sum = if sum == 0 { 0xffff } else { sum };
    udp[6..8].copy_from_slice(&sum.to_be_bytes());
    ip_packet(src.ip(), dst.ip(), PROTO_UDP, &udp)
}

/// An IPv4 or IPv6 packet carrying one TCP segment with no options.
pub fn tcp_packet(
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut tcp = Vec::with_capacity(20 + payload.len());
    tcp.extend_from_slice(&src.port().to_be_bytes());
    tcp.extend_from_slice(&dst.port().to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.extend_from_slice(&[0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
    tcp.extend_from_slice(payload);
    let sum = transport_checksum(src.ip(), dst.ip(), PROTO_TCP, &tcp);
    tcp[16..18].copy_from_slice(&sum.to_be_bytes());
    ip_packet(src.ip(), dst.ip(), PROTO_TCP, &tcp)
}

fn ip_packet(src: IpAddr, dst: IpAddr, protocol: u8, payload: &[u8]) -> Vec<u8> {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = (20 + payload.len()) as u16;
            let mut p = Vec::with_capacity(usize::from(total));
            p.extend_from_slice(&[0x45, 0]);
            p.extend_from_slice(&total.to_be_bytes());
            p.extend_from_slice(&[0, 0, 0x40, 0, 64, protocol, 0, 0]);
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
            let sum = finish(sum_words(0, &p));
            p[10..12].copy_from_slice(&sum.to_be_bytes());
            p.extend_from_slice(payload);
            p
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut p = Vec::with_capacity(40 + payload.len());
            p.extend_from_slice(&[0x60, 0, 0, 0]);
            p.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            p.extend_from_slice(&[protocol, 64]);
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
            p.extend_from_slice(payload);
            p
        }
        _ => panic!("mixed IP versions: {src} -> {dst}"),
    }
}

fn transport_checksum(src: IpAddr, dst: IpAddr, protocol: u8, segment: &[u8]) -> u16 {
    let mut acc = 0u32;
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            acc = sum_words(acc, &s.octets());
            acc = sum_words(acc, &d.octets());
            acc += u32::from(protocol);
            acc += segment.len() as u32;
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            acc = sum_words(acc, &s.octets());
            acc = sum_words(acc, &d.octets());
            acc += segment.len() as u32;
            acc += u32::from(protocol);
        }
        _ => panic!("mixed IP versions: {src} -> {dst}"),
    }
    finish(sum_words(acc, segment))
}

fn sum_words(mut acc: u32, data: &[u8]) -> u32 {
    let (words, rest) = data.as_chunks::<2>();
    for w in words {
        acc += u32::from(u16::from_be_bytes(*w));
    }
    if let [last] = rest {
        acc += u32::from(*last) << 8;
    }
    acc
}

fn finish(mut acc: u32) -> u16 {
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// A record in a synthetic DNS response.
#[derive(Debug, Clone, Copy)]
pub enum DnsRecord<'a> {
    A([u8; 4]),
    Aaaa(Ipv6Addr),
    Cname(&'a str),
}

pub fn dns_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    push_name(&mut m, name);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&[0, 1]);
    m
}

/// A response to an A query for `name`. A CNAME record renames the chain:
/// records after it are owned by the CNAME target, written as a compression
/// pointer to wherever that name was last written.
pub fn dns_response(id: u16, name: &str, records: &[DnsRecord<'_>]) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&[0x81, 0x80, 0, 1, 0, records.len() as u8, 0, 0, 0, 0]);
    let mut owner_at = m.len() as u16;
    push_name(&mut m, name);
    m.extend_from_slice(&[0, 1, 0, 1]);
    for rec in records {
        m.extend_from_slice(&(0xc000 | owner_at).to_be_bytes());
        let (rtype, rdata): (u16, Vec<u8>) = match *rec {
            DnsRecord::A(a) => (crate::dns::TYPE_A, a.to_vec()),
            DnsRecord::Aaaa(a) => (crate::dns::TYPE_AAAA, a.octets().to_vec()),
            DnsRecord::Cname(target) => {
                let mut d = Vec::new();
                push_name(&mut d, target);
                (crate::dns::TYPE_CNAME, d)
            }
        };
        m.extend_from_slice(&rtype.to_be_bytes());
        m.extend_from_slice(&[0, 1, 0, 0, 0x0e, 0x10]); // class IN, TTL 3600
        m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        if matches!(rec, DnsRecord::Cname(_)) {
            owner_at = m.len() as u16;
        }
        m.extend_from_slice(&rdata);
    }
    m
}

fn push_name(m: &mut Vec<u8>, name: &str) {
    for label in name.split('.').filter(|l| !l.is_empty()) {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
}

/// A minimal TLS 1.3-style ClientHello record. `padding` adds an extension of
/// that many bytes, to model large post-quantum key shares.
pub fn client_hello(sni: Option<&str>, padding: usize) -> Vec<u8> {
    let mut exts = Vec::new();
    if let Some(name) = sni {
        let n = name.as_bytes();
        exts.extend_from_slice(&0u16.to_be_bytes());
        exts.extend_from_slice(&((n.len() + 5) as u16).to_be_bytes());
        exts.extend_from_slice(&((n.len() + 3) as u16).to_be_bytes());
        exts.push(0);
        exts.extend_from_slice(&(n.len() as u16).to_be_bytes());
        exts.extend_from_slice(n);
    }
    if padding > 0 {
        exts.extend_from_slice(&21u16.to_be_bytes()); // padding extension
        exts.extend_from_slice(&(padding as u16).to_be_bytes());
        exts.extend(std::iter::repeat_n(0, padding));
    }
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0x42; 32]); // random
    body.push(0); // session id
    body.extend_from_slice(&[0, 2, 0x13, 0x01]); // one cipher suite
    body.extend_from_slice(&[1, 0]); // null compression
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut hs = vec![1];
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(&body);

    let mut rec = vec![22, 3, 1];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

/// Client Initial datagrams carrying `handshake` (a bare ClientHello
/// message) in `packets` CRYPTO fragments, one packet per datagram, each
/// padded to 1200 bytes. Fragments go out last-first, the way Chrome
/// scrambles them, so readers must reassemble by offset.
pub fn quic_initials(version: u32, dcid: &[u8], handshake: &[u8], packets: usize) -> Vec<Vec<u8>> {
    use crate::quic::{self, VERSION_2};
    use aes_gcm::aead::AeadInOut;
    use aes_gcm::{Aes128Gcm, KeyInit, Nonce};

    let keys = quic::client_initial_keys(version, dcid).expect("supported version");
    let packets = packets.max(1);
    let chunk = handshake.len().div_ceil(packets);
    let mut fragments: Vec<(usize, &[u8])> = handshake
        .chunks(chunk)
        .enumerate()
        .map(|(i, c)| (i * chunk, c))
        .collect();
    fragments.reverse();

    let initial_type: u8 = if version == VERSION_2 { 1 } else { 0 };
    fragments
        .iter()
        .enumerate()
        .map(|(pn, (offset, data))| {
            let mut payload = vec![0x06];
            push_varint(&mut payload, *offset as u64);
            push_varint(&mut payload, data.len() as u64);
            payload.extend_from_slice(data);

            let pn_len = 2usize;
            let mut header = vec![0xc0 | (initial_type << 4) | (pn_len as u8 - 1)];
            header.extend_from_slice(&version.to_be_bytes());
            header.push(dcid.len() as u8);
            header.extend_from_slice(dcid);
            header.push(0); // no source connection ID
            header.push(0); // no token
            // Pad the payload so the datagram reaches 1200 bytes.
            let fixed = header.len() + 2 + pn_len + 16;
            if fixed + payload.len() < 1200 {
                payload.resize(1200 - fixed, 0);
            }
            let length = (pn_len + payload.len() + 16) as u64;
            header.extend_from_slice(&(0x4000 | length as u16).to_be_bytes());
            let pn_offset = header.len();
            header.extend_from_slice(&(pn as u16).to_be_bytes());

            let mut nonce = keys.iv;
            for (i, b) in (pn as u64).to_be_bytes().iter().enumerate() {
                nonce[4 + i] ^= b;
            }
            let cipher = Aes128Gcm::new(&keys.key.into());
            let tag = cipher
                .encrypt_inout_detached(&Nonce::from(nonce), &header, payload.as_mut_slice().into())
                .expect("encrypt");
            let mut packet = header;
            packet.extend_from_slice(&payload);
            packet.extend_from_slice(&tag);

            let sample: [u8; 16] = packet[pn_offset + 4..pn_offset + 20]
                .try_into()
                .expect("sample");
            let mask = quic::header_mask(&keys.hp, &sample);
            packet[0] ^= mask[0] & 0x0f;
            for i in 0..pn_len {
                packet[pn_offset + i] ^= mask[1 + i];
            }
            packet
        })
        .collect()
}

fn push_varint(out: &mut Vec<u8>, v: u64) {
    match v {
        0..=63 => out.push(v as u8),
        64..=16383 => out.extend_from_slice(&(0x4000 | v as u16).to_be_bytes()),
        _ => out.extend_from_slice(&(0x8000_0000 | v as u32).to_be_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ip, transport};

    #[test]
    fn udp_packet_round_trips_v4_and_v6() {
        for (src, dst) in [
            ("10.0.0.2:5000", "1.1.1.1:53"),
            ("[fd00::2]:5000", "[2606:4700::1111]:53"),
        ] {
            let (src, dst): (SocketAddr, SocketAddr) = (src.parse().unwrap(), dst.parse().unwrap());
            let p = udp_packet(src, dst, b"payload");
            let parsed = ip::parse(&p).unwrap();
            assert_eq!((parsed.src, parsed.dst), (src.ip(), dst.ip()));
            let udp = transport::parse_udp(parsed.payload).unwrap();
            assert_eq!(udp.dst_port, 53);
            assert_eq!(udp.payload, b"payload");
            // A correct checksum sums to zero over the pseudo-header.
            assert_eq!(
                transport_checksum(src.ip(), dst.ip(), PROTO_UDP, parsed.payload),
                0
            );
        }
    }

    #[test]
    fn ipv4_header_checksum_verifies() {
        let p = udp_packet(
            "10.0.0.2:1".parse().unwrap(),
            "10.0.0.1:2".parse().unwrap(),
            b"x",
        );
        assert_eq!(finish(sum_words(0, &p[..20])), 0);
    }
}
