//! IPv4 and IPv6 headers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IP version of a raw packet as read from a tunnel interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

/// Reads the IP version from the first nibble of a raw packet.
pub fn ip_version(packet: &[u8]) -> Option<IpVersion> {
    match packet.first()? >> 4 {
        4 => Some(IpVersion::V4),
        6 => Some(IpVersion::V6),
        _ => None,
    }
}

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_ICMPV6: u8 = 58;

/// A parsed IP header and its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpPacket<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    /// Upper-layer protocol number, after any IPv6 extension headers.
    pub protocol: u8,
    /// The upper-layer payload. Empty for non-first fragments.
    pub payload: &'a [u8],
    /// True for a fragment other than the first; it carries no transport header.
    pub later_fragment: bool,
    /// Total packet length as declared by the header.
    pub total_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpError {
    Truncated,
    BadVersion,
    BadHeader,
}

pub fn parse(packet: &[u8]) -> Result<IpPacket<'_>, IpError> {
    match ip_version(packet) {
        Some(IpVersion::V4) => parse_v4(packet),
        Some(IpVersion::V6) => parse_v6(packet),
        None => Err(if packet.is_empty() {
            IpError::Truncated
        } else {
            IpError::BadVersion
        }),
    }
}

fn parse_v4(packet: &[u8]) -> Result<IpPacket<'_>, IpError> {
    if packet.len() < 20 {
        return Err(IpError::Truncated);
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < 20 {
        return Err(IpError::BadHeader);
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < ihl {
        return Err(IpError::BadHeader);
    }
    if packet.len() < total_len {
        return Err(IpError::Truncated);
    }
    let frag = u16::from_be_bytes([packet[6], packet[7]]);
    let offset = frag & 0x1fff;
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let later_fragment = offset != 0;
    Ok(IpPacket {
        src: src.into(),
        dst: dst.into(),
        protocol: packet[9],
        payload: if later_fragment {
            &[]
        } else {
            &packet[ihl..total_len]
        },
        later_fragment,
        total_len,
    })
}

fn parse_v6(packet: &[u8]) -> Result<IpPacket<'_>, IpError> {
    if packet.len() < 40 {
        return Err(IpError::Truncated);
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_len = 40 + payload_len;
    if packet.len() < total_len {
        return Err(IpError::Truncated);
    }
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap_or_default());
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap_or_default());

    let mut next = packet[6];
    let mut at = 40;
    let mut later_fragment = false;
    // Walk extension headers. Bounded: each step advances at least 8 bytes.
    loop {
        match next {
            // Hop-by-hop, routing, destination options.
            0 | 43 | 60 => {
                let hdr = packet.get(at..at + 2).ok_or(IpError::Truncated)?;
                next = hdr[0];
                at += (usize::from(hdr[1]) + 1) * 8;
            }
            // Fragment.
            44 => {
                let hdr = packet.get(at..at + 8).ok_or(IpError::Truncated)?;
                next = hdr[0];
                let offset = u16::from_be_bytes([hdr[2], hdr[3]]) >> 3;
                later_fragment = offset != 0;
                at += 8;
            }
            _ => break,
        }
        if at > total_len {
            return Err(IpError::Truncated);
        }
    }
    Ok(IpPacket {
        src: src.into(),
        dst: dst.into(),
        protocol: next,
        payload: if later_fragment {
            &[]
        } else {
            &packet[at..total_len]
        },
        later_fragment,
        total_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn v4_header(protocol: u8, payload_len: usize) -> Vec<u8> {
        let total = (20 + payload_len) as u16;
        let mut p = vec![
            0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, protocol, 0, 0, 10, 0, 0, 2, 93, 184, 216, 34,
        ];
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p
    }

    #[test]
    fn reads_version_nibble() {
        assert_eq!(ip_version(&[0x45, 0x00]), Some(IpVersion::V4));
        assert_eq!(ip_version(&[0x60, 0x00]), Some(IpVersion::V6));
        assert_eq!(ip_version(&[0x00]), None);
        assert_eq!(ip_version(&[]), None);
    }

    #[test]
    fn parses_ipv4() {
        let mut p = v4_header(PROTO_UDP, 4);
        p.extend_from_slice(&[1, 2, 3, 4]);
        let ip = parse(&p).unwrap();
        assert_eq!(ip.src, "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(ip.dst, "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(ip.protocol, PROTO_UDP);
        assert_eq!(ip.payload, &[1, 2, 3, 4]);
    }

    #[test]
    fn ipv4_ignores_trailing_padding() {
        let mut p = v4_header(PROTO_UDP, 2);
        p.extend_from_slice(&[9, 9, 0, 0, 0]);
        assert_eq!(parse(&p).unwrap().payload, &[9, 9]);
    }

    #[test]
    fn ipv4_rejects_truncation() {
        let p = v4_header(PROTO_UDP, 10);
        assert_eq!(parse(&p), Err(IpError::Truncated));
    }

    #[test]
    fn parses_ipv6_with_extension_header() {
        let mut p = vec![0x60, 0, 0, 0, 0, 0, 0 /* hop-by-hop */, 64];
        p.extend_from_slice(&"fd00::2".parse::<Ipv6Addr>().unwrap().octets());
        p.extend_from_slice(&"2606:4700::1111".parse::<Ipv6Addr>().unwrap().octets());
        // Hop-by-hop: next = UDP, length 0 (8 bytes).
        p.extend_from_slice(&[PROTO_UDP, 0, 0, 0, 0, 0, 0, 0]);
        p.extend_from_slice(&[7, 7]);
        let len = (p.len() - 40) as u16;
        p[4..6].copy_from_slice(&len.to_be_bytes());
        let ip = parse(&p).unwrap();
        assert_eq!(ip.protocol, PROTO_UDP);
        assert_eq!(ip.payload, &[7, 7]);
        assert_eq!(ip.dst, "2606:4700::1111".parse::<IpAddr>().unwrap());
    }
}
