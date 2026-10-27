//! The snapshot: how a rule set travels from the app to the capture extension.
//!
//! One immutable file, written whole to a temporary name and renamed into
//! place, so a reader sees the old rules or the new ones, never a mixture.
//! Panic, mode and the essentials switch live in the header, so the panic
//! button is a rewrite of a few bytes' worth of rules, not a new design.
//!
//! Layout, little-endian, version 1:
//!
//! ```text
//!  0  4  magic "FLRS"
//!  4  2  format version
//!  6  1  mode: 0 allow-all, 1 block-all, 2 lockdown
//!  7  1  flags: bit 0 panic, bit 1 essentials (other bits must be 0)
//!  8  8  generation: the version number; newer files have bigger ones
//! 16  4  rule count
//! 20  4  string table length
//! 24  4  CRC-32 of bytes 0 to 23 and everything from byte 28 on, so a
//!        flipped panic bit or generation is caught like any other damage
//! 28     rule records, 24 bytes each
//!        string table (domain names, address bytes, app ids)
//! ```
//!
//! A rule record: id u32 | action u8 (0 allow, 1 block) | destination kind u8
//! (0 any, 1 domain, 2 subdomains, 3 range, 4 address) | transport u8 (0 any,
//! 1 tcp, 2 udp) | prefix u8 | port from u16 | port to u16 (both 0 for any) |
//! destination offset u32 | destination length u16 | app length u16 | app
//! offset u32. Address bytes are 4 or 16, big-endian as on the wire.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use flynn_types::{Transport, crc32};

use crate::SNAPSHOT_FORMAT_VERSION;
use crate::model::{Action, Config, Dest, MAX_RULES, Mode, PortRange, Rule, RuleError, addr_bits};
use crate::ruleset::RuleSet;

const MAGIC: &[u8; 4] = b"FLRS";
const HEADER_LEN: usize = 28;
const RECORD_LEN: usize = 24;
/// Larger than any real table: 200,000 rules of long names fit well inside.
const MAX_TABLE: usize = 64 * 1024 * 1024;

/// A decoded snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub config: Config,
    pub generation: u64,
}

impl Snapshot {
    pub fn compile(&self) -> Result<RuleSet, RuleError> {
        RuleSet::compile(&self.config, self.generation)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SnapshotError {
    #[error("the file is too short to be a rule snapshot")]
    TooShort,
    #[error("not a rule snapshot (wrong magic)")]
    BadMagic,
    #[error(
        "snapshot version {0} is not supported (this build reads version {SNAPSHOT_FORMAT_VERSION})"
    )]
    UnsupportedVersion(u16),
    #[error("the snapshot's checksum does not match: the file is damaged")]
    BadChecksum,
    #[error("the snapshot is damaged: {0}")]
    Corrupt(&'static str),
    #[error("the snapshot holds an invalid rule: {0}")]
    Invalid(#[from] RuleError),
}

/// Encodes `config` (normalised first) as a snapshot.
pub fn encode(config: &Config, generation: u64) -> Result<Vec<u8>, RuleError> {
    let config = config.normalize()?;
    let mut records = Vec::with_capacity(config.rules.len() * RECORD_LEN);
    let mut table: Vec<u8> = Vec::new();

    for r in &config.rules {
        let (kind, prefix, dest): (u8, u8, Vec<u8>) = match &r.dest {
            Dest::Any => (0, 0, Vec::new()),
            Dest::Domain(d) => (1, 0, d.as_bytes().to_vec()),
            Dest::Subdomains(d) => (2, 0, d.as_bytes().to_vec()),
            Dest::Cidr(a, p) => (3, *p, addr_bytes(*a)),
            Dest::Address(a) => (4, addr_bits(*a), addr_bytes(*a)),
        };
        let app = r.app.as_deref().unwrap_or("").as_bytes();
        let dest_off = table.len() as u32;
        table.extend_from_slice(&dest);
        let app_off = table.len() as u32;
        table.extend_from_slice(app);

        records.extend_from_slice(&r.id.to_le_bytes());
        records.push(match r.action {
            Action::Allow => 0,
            Action::Block => 1,
        });
        records.push(kind);
        records.push(match r.transport {
            None => 0,
            Some(Transport::Tcp) => 1,
            Some(Transport::Udp) => 2,
        });
        records.push(prefix);
        let (from, to) = r.ports.map_or((0, 0), |p| (p.from, p.to));
        records.extend_from_slice(&from.to_le_bytes());
        records.extend_from_slice(&to.to_le_bytes());
        records.extend_from_slice(&dest_off.to_le_bytes());
        records.extend_from_slice(&(dest.len() as u16).to_le_bytes());
        records.extend_from_slice(&(app.len() as u16).to_le_bytes());
        records.extend_from_slice(&app_off.to_le_bytes());
    }

    let mut body = records;
    body.extend_from_slice(&table);

    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&SNAPSHOT_FORMAT_VERSION.to_le_bytes());
    out.push(match config.mode {
        Mode::AllowAll => 0,
        Mode::BlockAll => 1,
        Mode::Lockdown => 2,
    });
    out.push(u8::from(config.panic) | (u8::from(config.essentials) << 1));
    out.extend_from_slice(&generation.to_le_bytes());
    out.extend_from_slice(&(config.rules.len() as u32).to_le_bytes());
    out.extend_from_slice(&(table.len() as u32).to_le_bytes());
    let crc = checksum(&out[..24], &body);
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decodes and validates a snapshot. Never panics, whatever the bytes.
pub fn decode(bytes: &[u8]) -> Result<Snapshot, SnapshotError> {
    if bytes.len() < HEADER_LEN {
        return Err(SnapshotError::TooShort);
    }
    if &bytes[..4] != MAGIC {
        return Err(SnapshotError::BadMagic);
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != SNAPSHOT_FORMAT_VERSION {
        return Err(SnapshotError::UnsupportedVersion(version));
    }
    let mode = match bytes[6] {
        0 => Mode::AllowAll,
        1 => Mode::BlockAll,
        2 => Mode::Lockdown,
        _ => return Err(SnapshotError::Corrupt("unknown mode")),
    };
    let flags = bytes[7];
    if flags & !0b11 != 0 {
        return Err(SnapshotError::Corrupt("unknown flags"));
    }
    let generation = u64::from_le_bytes(array8(&bytes[8..16]));
    let count = u32::from_le_bytes(array4(&bytes[16..20])) as usize;
    let table_len = u32::from_le_bytes(array4(&bytes[20..24])) as usize;
    let crc = u32::from_le_bytes(array4(&bytes[24..28]));
    if count > MAX_RULES || table_len > MAX_TABLE {
        return Err(SnapshotError::Corrupt("implausible sizes"));
    }
    let records_len = count * RECORD_LEN;
    if bytes.len() != HEADER_LEN + records_len + table_len {
        return Err(SnapshotError::Corrupt(
            "the length does not match the header",
        ));
    }
    let body = &bytes[HEADER_LEN..];
    if checksum(&bytes[..24], body) != crc {
        return Err(SnapshotError::BadChecksum);
    }
    let (records, table) = body.split_at(records_len);

    let mut rules = Vec::with_capacity(count);
    for rec in records.as_chunks::<RECORD_LEN>().0 {
        let id = u32::from_le_bytes(array4(&rec[0..4]));
        let action = match rec[4] {
            0 => Action::Allow,
            1 => Action::Block,
            _ => return Err(SnapshotError::Corrupt("unknown action")),
        };
        let kind = rec[5];
        let transport = match rec[6] {
            0 => None,
            1 => Some(Transport::Tcp),
            2 => Some(Transport::Udp),
            _ => return Err(SnapshotError::Corrupt("unknown transport")),
        };
        let prefix = rec[7];
        let port_from = u16::from_le_bytes([rec[8], rec[9]]);
        let port_to = u16::from_le_bytes([rec[10], rec[11]]);
        let dest_off = u32::from_le_bytes(array4(&rec[12..16])) as usize;
        let dest_len = usize::from(u16::from_le_bytes([rec[16], rec[17]]));
        let app_len = usize::from(u16::from_le_bytes([rec[18], rec[19]]));
        let app_off = u32::from_le_bytes(array4(&rec[20..24])) as usize;

        let dest_bytes = slice(table, dest_off, dest_len)?;
        let dest = match kind {
            0 => Dest::Any,
            1 => Dest::Domain(utf8(dest_bytes)?),
            2 => Dest::Subdomains(utf8(dest_bytes)?),
            3 => Dest::Cidr(addr_from(dest_bytes)?, prefix),
            4 => Dest::Address(addr_from(dest_bytes)?),
            _ => return Err(SnapshotError::Corrupt("unknown destination kind")),
        };
        let app = if app_len == 0 {
            None
        } else {
            Some(utf8(slice(table, app_off, app_len)?)?)
        };
        let ports = match (port_from, port_to) {
            (0, 0) => None,
            (from, to) => Some(PortRange { from, to }),
        };
        rules.push(Rule {
            id,
            action,
            dest,
            app,
            ports,
            transport,
        });
    }

    let config = Config {
        mode,
        panic: flags & 1 != 0,
        essentials: flags & 2 != 0,
        rules,
    }
    .normalize()?;
    Ok(Snapshot { config, generation })
}

/// The checksum covers the header (without its own field) and the body.
fn checksum(header: &[u8], body: &[u8]) -> u32 {
    let mut all = Vec::with_capacity(header.len() + body.len());
    all.extend_from_slice(header);
    all.extend_from_slice(body);
    crc32(&all)
}

fn array4(b: &[u8]) -> [u8; 4] {
    [b[0], b[1], b[2], b[3]]
}

fn array8(b: &[u8]) -> [u8; 8] {
    [b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]
}

fn slice(table: &[u8], off: usize, len: usize) -> Result<&[u8], SnapshotError> {
    off.checked_add(len)
        .and_then(|end| table.get(off..end))
        .ok_or(SnapshotError::Corrupt("a string points outside the table"))
}

fn utf8(b: &[u8]) -> Result<String, SnapshotError> {
    String::from_utf8(b.to_vec()).map_err(|_| SnapshotError::Corrupt("a string is not UTF-8"))
}

fn addr_bytes(a: IpAddr) -> Vec<u8> {
    match a {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

fn addr_from(b: &[u8]) -> Result<IpAddr, SnapshotError> {
    match b.len() {
        4 => Ok(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))),
        16 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(b);
            Ok(IpAddr::V6(Ipv6Addr::from(o)))
        }
        _ => Err(SnapshotError::Corrupt("an address is not 4 or 16 bytes")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Config {
        Config {
            mode: Mode::BlockAll,
            panic: false,
            essentials: true,
            rules: vec![
                Rule {
                    id: 1,
                    action: Action::Block,
                    dest: Dest::Subdomains("tracker.test".into()),
                    app: None,
                    ports: None,
                    transport: None,
                },
                Rule {
                    id: 2,
                    action: Action::Allow,
                    dest: Dest::Cidr("10.0.0.0".parse().unwrap(), 8),
                    app: Some("com.example.app".into()),
                    ports: Some(PortRange { from: 80, to: 90 }),
                    transport: Some(Transport::Tcp),
                },
                Rule {
                    id: 3,
                    action: Action::Block,
                    dest: Dest::Address("2001:db8::1".parse().unwrap()),
                    app: None,
                    ports: None,
                    transport: Some(Transport::Udp),
                },
                Rule {
                    id: 9,
                    action: Action::Allow,
                    dest: Dest::Domain("www.example.com".into()),
                    app: None,
                    ports: Some(PortRange { from: 443, to: 443 }),
                    transport: None,
                },
            ],
        }
    }

    #[test]
    fn round_trips() {
        let bytes = encode(&sample(), 42).unwrap();
        let snap = decode(&bytes).unwrap();
        assert_eq!(snap.generation, 42);
        assert_eq!(snap.config, sample().normalize().unwrap());
    }

    #[test]
    fn header_carries_panic_mode_and_essentials() {
        let mut c = sample();
        c.panic = true;
        c.essentials = false;
        c.mode = Mode::Lockdown;
        let snap = decode(&encode(&c, 1).unwrap()).unwrap();
        assert!(snap.config.panic);
        assert!(!snap.config.essentials);
        assert_eq!(snap.config.mode, Mode::Lockdown);
    }

    #[test]
    fn an_empty_rule_set_round_trips() {
        let snap = decode(&encode(&Config::default(), 7).unwrap()).unwrap();
        assert_eq!(snap.config, Config::default());
    }

    #[test]
    fn every_single_byte_flip_is_detected() {
        let bytes = encode(&sample(), 5).unwrap();
        for i in 0..bytes.len() {
            let mut bad = bytes.clone();
            bad[i] ^= 0x01;
            assert!(decode(&bad).is_err(), "a flip at byte {i} went unnoticed");
        }
    }

    #[test]
    fn truncation_and_extension_are_rejected() {
        let bytes = encode(&sample(), 5).unwrap();
        for len in 0..bytes.len() {
            assert!(decode(&bytes[..len]).is_err(), "length {len}");
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(decode(&longer).is_err());
    }

    #[test]
    fn other_versions_and_garbage_are_refused_clearly() {
        let mut bytes = encode(&sample(), 5).unwrap();
        bytes[4] = 9;
        assert_eq!(decode(&bytes), Err(SnapshotError::UnsupportedVersion(9)));
        assert_eq!(
            decode(b"not a snapshot at all, but long enough......"),
            Err(SnapshotError::BadMagic)
        );
        assert_eq!(decode(b"x"), Err(SnapshotError::TooShort));
    }

    #[test]
    fn an_invalid_config_is_refused_at_encode() {
        let mut c = sample();
        c.rules[1].id = 1;
        assert_eq!(encode(&c, 1), Err(RuleError::DuplicateId(1)));
    }

    #[test]
    fn a_snapshot_compiles_to_a_working_rule_set() {
        let snap = decode(&encode(&sample(), 11).unwrap()).unwrap();
        let rules = snap.compile().unwrap();
        assert_eq!(rules.generation(), 11);
        assert_eq!(rules.rule_count(), 4);
        assert_eq!(rules.mode(), Mode::BlockAll);
    }
}
