//! Reading pcap and pcapng captures, and writing pcap.
//!
//! Captures from tcpdump on a utun interface (link type NULL), Ethernet,
//! and raw IP are supported; anything else is skipped and counted.

use std::io::{self, Write};

/// One captured packet, reduced to its IP bytes.
pub struct Packet {
    pub at_ms: i64,
    pub ip: Vec<u8>,
}

pub struct Capture {
    pub packets: Vec<Packet>,
    /// Records whose link type or framing could not be reduced to IP.
    pub unsupported: u64,
}

const LINKTYPE_NULL: u32 = 0;
const LINKTYPE_ETHERNET: u32 = 1;
const LINKTYPE_RAW: u32 = 101;
const LINKTYPE_RAW_BSD: u32 = 12;
const LINKTYPE_IPV4: u32 = 228;
const LINKTYPE_IPV6: u32 = 229;

pub fn read(data: &[u8]) -> io::Result<Capture> {
    let magic = data.get(..4).ok_or_else(|| bad("file too short"))?;
    match magic {
        [0x0a, 0x0d, 0x0d, 0x0a] => read_pcapng(data),
        _ => read_pcap(data),
    }
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

#[derive(Clone, Copy)]
struct Endian(bool); // true = little

impl Endian {
    fn u16(self, b: &[u8]) -> u16 {
        let a = [b[0], b[1]];
        if self.0 {
            u16::from_le_bytes(a)
        } else {
            u16::from_be_bytes(a)
        }
    }
    fn u32(self, b: &[u8]) -> u32 {
        let a = [b[0], b[1], b[2], b[3]];
        if self.0 {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        }
    }
}

fn read_pcap(data: &[u8]) -> io::Result<Capture> {
    if data.len() < 24 {
        return Err(bad("pcap header too short"));
    }
    let (endian, nanos) = match [data[0], data[1], data[2], data[3]] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (Endian(true), false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (Endian(false), false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (Endian(true), true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (Endian(false), true),
        _ => return Err(bad("not a pcap or pcapng file")),
    };
    let linktype = endian.u32(&data[20..24]) & 0x0fff_ffff;
    let mut capture = Capture {
        packets: Vec::new(),
        unsupported: 0,
    };
    let mut at = 24;
    while at + 16 <= data.len() {
        let secs = i64::from(endian.u32(&data[at..]));
        let frac = i64::from(endian.u32(&data[at + 4..]));
        let incl = endian.u32(&data[at + 8..]) as usize;
        let body = data
            .get(at + 16..at + 16 + incl)
            .ok_or_else(|| bad("truncated pcap record"))?;
        let at_ms = secs * 1000 + if nanos { frac / 1_000_000 } else { frac / 1000 };
        push(&mut capture, linktype, at_ms, body);
        at += 16 + incl;
    }
    Ok(capture)
}

fn read_pcapng(data: &[u8]) -> io::Result<Capture> {
    let mut capture = Capture {
        packets: Vec::new(),
        unsupported: 0,
    };
    let mut endian = Endian(true);
    // Per interface: link type and timestamp units per second.
    let mut interfaces: Vec<(u32, u64)> = Vec::new();
    let mut at = 0;
    while at + 12 <= data.len() {
        let block_type_raw = &data[at..at + 4];
        if block_type_raw == [0x0a, 0x0d, 0x0d, 0x0a] {
            // Section header: the byte-order magic decides endianness.
            let bom = data
                .get(at + 8..at + 12)
                .ok_or_else(|| bad("truncated section header"))?;
            endian = Endian(bom == [0x4d, 0x3c, 0x2b, 0x1a]);
            interfaces.clear();
        }
        let block_type = endian.u32(block_type_raw);
        let len = endian.u32(&data[at + 4..]) as usize;
        if len < 12 || at + len > data.len() {
            return Err(bad("bad pcapng block length"));
        }
        let body = &data[at + 8..at + len - 4];
        match block_type {
            // Interface description.
            1 if body.len() >= 8 => {
                let linktype = u32::from(endian.u16(&body[0..2]));
                interfaces.push((linktype, if_tsresol(endian, &body[8..])));
            }
            // Enhanced packet.
            6 if body.len() >= 20 => {
                let iface = endian.u32(&body[0..4]) as usize;
                let ts = (u64::from(endian.u32(&body[4..8])) << 32)
                    | u64::from(endian.u32(&body[8..12]));
                let incl = endian.u32(&body[12..16]) as usize;
                match (interfaces.get(iface), body.get(20..20 + incl)) {
                    (Some(&(linktype, per_sec)), Some(packet)) => {
                        let at_ms = (u128::from(ts) * 1000 / u128::from(per_sec.max(1))) as i64;
                        push(&mut capture, linktype, at_ms, packet);
                    }
                    _ => capture.unsupported += 1,
                }
            }
            _ => {}
        }
        at += len;
    }
    Ok(capture)
}

/// Timestamp resolution from an interface block's options; default 10^-6.
fn if_tsresol(endian: Endian, mut opts: &[u8]) -> u64 {
    while opts.len() >= 4 {
        let code = endian.u16(&opts[0..2]);
        let len = usize::from(endian.u16(&opts[2..4]));
        let Some(value) = opts.get(4..4 + len) else {
            break;
        };
        if code == 9 && len == 1 {
            let v = value[0];
            let exp = u32::from(v & 0x7f);
            return if v & 0x80 != 0 {
                2u64.saturating_pow(exp)
            } else {
                10u64.saturating_pow(exp)
            };
        }
        if code == 0 {
            break;
        }
        opts = &opts[(4 + len).next_multiple_of(4).min(opts.len())..];
    }
    1_000_000
}

fn push(capture: &mut Capture, linktype: u32, at_ms: i64, frame: &[u8]) {
    let ip = match linktype {
        LINKTYPE_RAW | LINKTYPE_RAW_BSD | LINKTYPE_IPV4 | LINKTYPE_IPV6 => Some(frame),
        // 4-byte address family, host byte order of the capturing machine.
        LINKTYPE_NULL => frame.get(4..),
        LINKTYPE_ETHERNET => ethernet_payload(frame),
        _ => None,
    };
    match ip {
        Some(ip) if !ip.is_empty() => capture.packets.push(Packet {
            at_ms,
            ip: ip.to_vec(),
        }),
        _ => capture.unsupported += 1,
    }
}

fn ethernet_payload(frame: &[u8]) -> Option<&[u8]> {
    let mut at = 12;
    let mut ethertype = u16::from_be_bytes([*frame.get(at)?, *frame.get(at + 1)?]);
    // Skip 802.1Q / 802.1ad VLAN tags.
    while ethertype == 0x8100 || ethertype == 0x88a8 {
        at += 4;
        ethertype = u16::from_be_bytes([*frame.get(at)?, *frame.get(at + 1)?]);
    }
    match ethertype {
        0x0800 | 0x86dd => frame.get(at + 2..),
        _ => None,
    }
}

/// Writes raw IP packets as a little-endian pcap with link type RAW.
pub fn write_raw<W: Write>(out: &mut W, packets: &[Packet]) -> io::Result<()> {
    out.write_all(&[0xd4, 0xc3, 0xb2, 0xa1])?;
    out.write_all(&2u16.to_le_bytes())?;
    out.write_all(&4u16.to_le_bytes())?;
    out.write_all(&[0; 8])?; // thiszone, sigfigs
    out.write_all(&65535u32.to_le_bytes())?;
    out.write_all(&LINKTYPE_RAW.to_le_bytes())?;
    for p in packets {
        out.write_all(&((p.at_ms / 1000) as u32).to_le_bytes())?;
        out.write_all(&(((p.at_ms % 1000) * 1000) as u32).to_le_bytes())?;
        out.write_all(&(p.ip.len() as u32).to_le_bytes())?;
        out.write_all(&(p.ip.len() as u32).to_le_bytes())?;
        out.write_all(&p.ip)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcap_round_trips() {
        let packets = vec![
            Packet {
                at_ms: 1_500,
                ip: vec![0x45, 1, 2],
            },
            Packet {
                at_ms: 2_250,
                ip: vec![0x60, 9],
            },
        ];
        let mut buf = Vec::new();
        write_raw(&mut buf, &packets).unwrap();
        let cap = read(&buf).unwrap();
        assert_eq!(cap.packets.len(), 2);
        assert_eq!(cap.packets[1].at_ms, 2_250);
        assert_eq!(cap.packets[1].ip, vec![0x60, 9]);
    }

    #[test]
    fn reads_pcapng_with_null_linktype() {
        let mut f = Vec::new();
        // Section header block, little endian.
        f.extend_from_slice(&[0x0a, 0x0d, 0x0d, 0x0a]);
        f.extend_from_slice(&28u32.to_le_bytes());
        f.extend_from_slice(&[0x4d, 0x3c, 0x2b, 0x1a, 1, 0, 0, 0]);
        f.extend_from_slice(&u64::MAX.to_le_bytes());
        f.extend_from_slice(&28u32.to_le_bytes());
        // Interface description block: link type NULL, no options.
        f.extend_from_slice(&1u32.to_le_bytes());
        f.extend_from_slice(&20u32.to_le_bytes());
        f.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        f.extend_from_slice(&20u32.to_le_bytes());
        // Enhanced packet block: AF header + 4 bytes of IP, ts = 3 s.
        let ts: u64 = 3_000_000;
        let frame = [2, 0, 0, 0, 0x45, 0, 0, 4];
        f.extend_from_slice(&6u32.to_le_bytes());
        f.extend_from_slice(&40u32.to_le_bytes());
        f.extend_from_slice(&0u32.to_le_bytes());
        f.extend_from_slice(&((ts >> 32) as u32).to_le_bytes());
        f.extend_from_slice(&(ts as u32).to_le_bytes());
        f.extend_from_slice(&8u32.to_le_bytes());
        f.extend_from_slice(&8u32.to_le_bytes());
        f.extend_from_slice(&frame);
        f.extend_from_slice(&40u32.to_le_bytes());
        let cap = read(&f).unwrap();
        assert_eq!(cap.packets.len(), 1);
        assert_eq!(cap.packets[0].at_ms, 3_000);
        assert_eq!(cap.packets[0].ip, vec![0x45, 0, 0, 4]);
    }

    #[test]
    fn strips_ethernet_with_vlan() {
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&[0x81, 0x00, 0, 5, 0x08, 0x00, 0x45, 0xaa]);
        assert_eq!(ethernet_payload(&frame), Some(&[0x45, 0xaa][..]));
    }
}
