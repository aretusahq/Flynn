//! The event spool: how the capture extension hands events to the app.
//!
//! Append-only segment files in the shared container. The extension never
//! opens a database; it writes fixed-layout records here, and the app reads
//! and ingests them (M5) and deletes what it has consumed. The format is the
//! same on every platform.
//!
//! Segment: `FLSP` magic, u16 version, u16 flags, then records. Record:
//! u32 payload length, u32 CRC-32 of the payload, payload. A reader stops
//! at the first record that is short or fails its CRC, which is how a
//! write cut off by jetsam shows up.
//!
//! At rest the files rely on iOS Data Protection (class C, the container
//! default). Encrypting the records themselves with a key from the shared
//! Keychain lands with the store in M5; `flags` reserves the bit.

use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use flynn_rules::Verdict;
use flynn_types::{AppId, Platform};

use crate::events::{CloseReason, Event, EventSink};
use crate::mem::MemSample;
use crate::{FlowKey, NameSource, StatsSnapshot, Transport};

const MAGIC: &[u8; 4] = b"FLSP";
pub const FORMAT_VERSION: u16 = 1;
const HEADER_LEN: usize = 8;
/// Records larger than this are corrupt by definition.
const MAX_RECORD: usize = 64 * 1024;

// ----- Writer ---------------------------------------------------------------

pub struct SpoolWriter {
    dir: PathBuf,
    segment_bytes: u64,
    max_segments: usize,
    seq: u64,
    file: BufWriter<File>,
    written: u64,
    scratch: Vec<u8>,
}

impl SpoolWriter {
    /// Opens a new segment after any already in `dir`. Never appends to an
    /// old segment, whose tail may be torn.
    pub fn open(dir: &Path, segment_bytes: u64, max_segments: usize) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let seq = segments(dir)?.last().map_or(1, |(seq, _)| seq + 1);
        let file = new_segment(dir, seq)?;
        let writer = Self {
            dir: dir.to_path_buf(),
            segment_bytes: segment_bytes.max(4096),
            max_segments: max_segments.max(2),
            seq,
            file,
            written: HEADER_LEN as u64,
            scratch: Vec::with_capacity(256),
        };
        writer.prune()?;
        Ok(writer)
    }

    pub fn append(&mut self, event: &Event) -> io::Result<()> {
        self.scratch.clear();
        encode(event, &mut self.scratch);
        let len = self.scratch.len() as u32;
        self.file.write_all(&len.to_le_bytes())?;
        self.file.write_all(&crc32(&self.scratch).to_le_bytes())?;
        self.file.write_all(&self.scratch)?;
        self.written += 8 + u64::from(len);
        if self.written >= self.segment_bytes {
            self.rotate()?;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.file.flush()?;
        self.seq += 1;
        self.file = new_segment(&self.dir, self.seq)?;
        self.written = HEADER_LEN as u64;
        self.prune()
    }

    /// Bounds disk use: if the app has not consumed old segments, the
    /// oldest go first.
    fn prune(&self) -> io::Result<()> {
        let all = segments(&self.dir)?;
        if all.len() > self.max_segments {
            for (_, path) in &all[..all.len() - self.max_segments] {
                let _ = fs::remove_file(path);
            }
        }
        Ok(())
    }
}

fn new_segment(dir: &Path, seq: u64) -> io::Result<BufWriter<File>> {
    let file = File::options()
        .create_new(true)
        .write(true)
        .open(segment_path(dir, seq))?;
    let mut file = BufWriter::with_capacity(16 * 1024, file);
    file.write_all(MAGIC)?;
    file.write_all(&FORMAT_VERSION.to_le_bytes())?;
    file.write_all(&0u16.to_le_bytes())?; // flags: plaintext records
    file.flush()?;
    Ok(file)
}

fn segment_path(dir: &Path, seq: u64) -> PathBuf {
    dir.join(format!("spool-{seq:016}.bin"))
}

/// Segment files in `dir`, oldest first.
pub fn segments(dir: &Path) -> io::Result<Vec<(u64, PathBuf)>> {
    let mut out = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };
    for entry in entries {
        let path = entry?.path();
        let seq = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_prefix("spool-"))
            .and_then(|n| n.strip_suffix(".bin"))
            .and_then(|n| n.parse::<u64>().ok());
        if let Some(seq) = seq {
            out.push((seq, path));
        }
    }
    out.sort_by_key(|(seq, _)| *seq);
    Ok(out)
}

/// An `EventSink` writing to the spool. Flushes when its buffer fills or
/// once a second, so the app sees events within about a second.
pub struct SpoolSink {
    inner: Mutex<SinkState>,
    flush_every: Duration,
}

struct SinkState {
    writer: SpoolWriter,
    dirty: bool,
    last_flush: Instant,
    errors: u64,
}

impl SpoolSink {
    pub fn open(dir: &Path) -> io::Result<Self> {
        Self::with_limits(dir, 256 * 1024, 64)
    }

    pub fn with_limits(dir: &Path, segment_bytes: u64, max_segments: usize) -> io::Result<Self> {
        Ok(Self {
            inner: Mutex::new(SinkState {
                writer: SpoolWriter::open(dir, segment_bytes, max_segments)?,
                dirty: false,
                last_flush: Instant::now(),
                errors: 0,
            }),
            flush_every: Duration::from_secs(1),
        })
    }

    /// Write failures so far (disk full, container gone).
    pub fn errors(&self) -> u64 {
        self.inner.lock().map_or(0, |s| s.errors)
    }

    pub fn flush(&self) {
        if let Ok(mut s) = self.inner.lock() {
            if s.writer.flush().is_err() {
                s.errors += 1;
            }
            s.dirty = false;
            s.last_flush = Instant::now();
        }
    }
}

impl EventSink for SpoolSink {
    fn emit(&self, event: Event) {
        let Ok(mut s) = self.inner.lock() else { return };
        if s.writer.append(&event).is_err() {
            s.errors += 1;
        }
        s.dirty = true;
    }

    fn tick(&self) {
        let Ok(mut s) = self.inner.lock() else { return };
        if s.dirty && s.last_flush.elapsed() >= self.flush_every {
            if s.writer.flush().is_err() {
                s.errors += 1;
            }
            s.dirty = false;
            s.last_flush = Instant::now();
        }
    }
}

impl Drop for SpoolSink {
    fn drop(&mut self) {
        self.flush();
    }
}

// ----- Reader ---------------------------------------------------------------

/// Reads every intact record in one segment. `complete` is false when the
/// segment ends in a torn or corrupt record (normal for the newest segment
/// while the extension is writing).
pub fn read_segment(path: &Path) -> io::Result<(Vec<Event>, bool)> {
    let data = fs::read(path)?;
    if data.len() < HEADER_LEN || &data[..4] != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a spool segment",
        ));
    }
    let version = u16::from_le_bytes([data[4], data[5]]);
    if version != FORMAT_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("spool version {version}"),
        ));
    }
    let mut events = Vec::new();
    let mut at = HEADER_LEN;
    while at < data.len() {
        let Some(head) = data.get(at..at + 8) else {
            return Ok((events, false));
        };
        let len = u32::from_le_bytes([head[0], head[1], head[2], head[3]]) as usize;
        let crc = u32::from_le_bytes([head[4], head[5], head[6], head[7]]);
        if len > MAX_RECORD {
            return Ok((events, false));
        }
        let Some(payload) = data.get(at + 8..at + 8 + len) else {
            return Ok((events, false));
        };
        if crc32(payload) != crc {
            return Ok((events, false));
        }
        match decode(payload) {
            Some(event) => events.push(event),
            None => return Ok((events, false)),
        }
        at += 8 + len;
    }
    Ok((events, true))
}

/// The newest `max` events across all segments, oldest first.
pub fn tail(dir: &Path, max: usize) -> io::Result<Vec<Event>> {
    let mut chunks: Vec<Vec<Event>> = Vec::new();
    let mut count = 0;
    for (_, path) in segments(dir)?.into_iter().rev() {
        let Ok((events, _)) = read_segment(&path) else {
            continue;
        };
        count += events.len();
        chunks.push(events);
        if count >= max {
            break;
        }
    }
    let mut all: Vec<Event> = chunks.into_iter().rev().flatten().collect();
    if all.len() > max {
        all.drain(..all.len() - max);
    }
    Ok(all)
}

// ----- Encoding -------------------------------------------------------------

const K_OPENED: u8 = 1;
const K_NAMED: u8 = 2;
const K_CLOSED: u8 = 3;
const K_DNS: u8 = 4;
const K_SAMPLE: u8 = 5;

fn encode(event: &Event, out: &mut Vec<u8>) {
    match event {
        Event::FlowOpened {
            id,
            at_ms,
            key,
            name,
            source,
            app,
            verdict,
        } => {
            out.push(K_OPENED);
            put_u64(out, *id);
            put_i64(out, *at_ms);
            out.push(match key.protocol {
                Transport::Tcp => 6,
                Transport::Udp => 17,
            });
            put_addr(out, key.src);
            put_addr(out, key.dst);
            put_opt_str(out, name.as_deref());
            out.push(source_code(*source));
            out.push(match verdict {
                Verdict::Allow => 0,
                Verdict::Block => 1,
            });
            match app {
                None => out.push(0),
                Some(app) => {
                    out.push(1);
                    out.push(platform_code(app.platform));
                    put_str(out, &app.id);
                    put_opt_str(out, app.display_name.as_deref());
                }
            }
        }
        Event::FlowNamed { id, name, source } => {
            out.push(K_NAMED);
            put_u64(out, *id);
            put_str(out, name);
            out.push(source_code(*source));
        }
        Event::FlowClosed {
            id,
            at_ms,
            bytes_up,
            bytes_down,
            reason,
        } => {
            out.push(K_CLOSED);
            put_u64(out, *id);
            put_i64(out, *at_ms);
            put_u64(out, *bytes_up);
            put_u64(out, *bytes_down);
            out.push(reason_code(*reason));
        }
        Event::DnsAnswer { at_ms, name, addrs } => {
            out.push(K_DNS);
            put_i64(out, *at_ms);
            put_str(out, name);
            let addrs = &addrs[..addrs.len().min(255)];
            out.push(addrs.len() as u8);
            for addr in addrs {
                put_ip(out, *addr);
            }
        }
        Event::Sample { at_ms, mem, stats } => {
            out.push(K_SAMPLE);
            put_i64(out, *at_ms);
            for v in [mem.footprint, mem.peak_footprint, mem.cpu_ms] {
                put_u64(out, v);
            }
            for v in [
                stats.packets_in,
                stats.packets_out,
                stats.bytes_up,
                stats.bytes_down,
                stats.tcp_active,
                stats.udp_active,
                stats.flows_opened,
                stats.flows_blocked,
                stats.connect_failed,
                stats.dropped,
            ] {
                put_u64(out, v);
            }
        }
    }
}

fn decode(payload: &[u8]) -> Option<Event> {
    let mut r = Cursor {
        buf: payload,
        at: 0,
    };
    let event = match r.u8()? {
        K_OPENED => {
            let id = r.u64()?;
            let at_ms = r.i64()?;
            let protocol = match r.u8()? {
                6 => Transport::Tcp,
                17 => Transport::Udp,
                _ => return None,
            };
            let src = r.addr()?;
            let dst = r.addr()?;
            let name = r.opt_str()?;
            let source = source_from(r.u8()?)?;
            let verdict = match r.u8()? {
                0 => Verdict::Allow,
                1 => Verdict::Block,
                _ => return None,
            };
            let app = match r.u8()? {
                0 => None,
                _ => Some(AppId {
                    platform: platform_from(r.u8()?)?,
                    id: r.str()?,
                    display_name: r.opt_str()?,
                }),
            };
            Event::FlowOpened {
                id,
                at_ms,
                key: FlowKey { protocol, src, dst },
                name,
                source,
                app,
                verdict,
            }
        }
        K_NAMED => Event::FlowNamed {
            id: r.u64()?,
            name: r.str()?,
            source: source_from(r.u8()?)?,
        },
        K_CLOSED => Event::FlowClosed {
            id: r.u64()?,
            at_ms: r.i64()?,
            bytes_up: r.u64()?,
            bytes_down: r.u64()?,
            reason: reason_from(r.u8()?)?,
        },
        K_DNS => {
            let at_ms = r.i64()?;
            let name = r.str()?;
            let n = r.u8()?;
            let addrs = (0..n).map(|_| r.ip()).collect::<Option<Vec<_>>>()?;
            Event::DnsAnswer { at_ms, name, addrs }
        }
        K_SAMPLE => {
            let at_ms = r.i64()?;
            let mem = MemSample {
                footprint: r.u64()?,
                peak_footprint: r.u64()?,
                cpu_ms: r.u64()?,
            };
            let stats = StatsSnapshot {
                packets_in: r.u64()?,
                packets_out: r.u64()?,
                bytes_up: r.u64()?,
                bytes_down: r.u64()?,
                tcp_active: r.u64()?,
                udp_active: r.u64()?,
                flows_opened: r.u64()?,
                flows_blocked: r.u64()?,
                connect_failed: r.u64()?,
                dropped: r.u64()?,
            };
            Event::Sample { at_ms, mem, stats }
        }
        _ => return None,
    };
    // Trailing bytes mean a newer writer; accept the fields we know.
    Some(event)
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn put_i64(out: &mut Vec<u8>, v: i64) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn put_str(out: &mut Vec<u8>, s: &str) {
    let bytes = &s.as_bytes()[..s.len().min(0xfffe)];
    out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(bytes);
}
fn put_opt_str(out: &mut Vec<u8>, s: Option<&str>) {
    match s {
        Some(s) => put_str(out, s),
        None => out.extend_from_slice(&0xffffu16.to_le_bytes()),
    }
}
fn put_ip(out: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(v4) => {
            out.push(4);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(6);
            out.extend_from_slice(&v6.octets());
        }
    }
}
fn put_addr(out: &mut Vec<u8>, addr: SocketAddr) {
    put_ip(out, addr.ip());
    out.extend_from_slice(&addr.port().to_le_bytes());
}

fn source_code(s: NameSource) -> u8 {
    match s {
        NameSource::None => 0,
        NameSource::Dns => 1,
        NameSource::Sni => 2,
    }
}
fn source_from(c: u8) -> Option<NameSource> {
    Some(match c {
        0 => NameSource::None,
        1 => NameSource::Dns,
        2 => NameSource::Sni,
        _ => return None,
    })
}
fn reason_code(r: CloseReason) -> u8 {
    match r {
        CloseReason::Normal => 0,
        CloseReason::Reset => 1,
        CloseReason::Blocked => 2,
        CloseReason::ConnectFailed => 3,
        CloseReason::Idle => 4,
        CloseReason::Capacity => 5,
        CloseReason::Shutdown => 6,
        CloseReason::ForcedTcp => 7,
    }
}
fn reason_from(c: u8) -> Option<CloseReason> {
    Some(match c {
        0 => CloseReason::Normal,
        1 => CloseReason::Reset,
        2 => CloseReason::Blocked,
        3 => CloseReason::ConnectFailed,
        4 => CloseReason::Idle,
        5 => CloseReason::Capacity,
        6 => CloseReason::Shutdown,
        7 => CloseReason::ForcedTcp,
        _ => return None,
    })
}
fn platform_code(p: Platform) -> u8 {
    match p {
        Platform::Ios => 1,
        Platform::Android => 2,
        Platform::Macos => 3,
        Platform::Windows => 4,
        Platform::Linux => 5,
    }
}
fn platform_from(c: u8) -> Option<Platform> {
    Some(match c {
        1 => Platform::Ios,
        2 => Platform::Android,
        3 => Platform::Macos,
        4 => Platform::Windows,
        5 => Platform::Linux,
        _ => return None,
    })
}

struct Cursor<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.buf.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_le_bytes([s[0], s[1]]))
    }
    fn u64(&mut self) -> Option<u64> {
        self.take(8)
            .map(|s| u64::from_le_bytes(s.try_into().unwrap_or_default()))
    }
    fn i64(&mut self) -> Option<i64> {
        self.u64().map(|v| v as i64)
    }
    fn str(&mut self) -> Option<String> {
        let len = usize::from(self.u16()?);
        String::from_utf8(self.take(len)?.to_vec()).ok()
    }
    fn opt_str(&mut self) -> Option<Option<String>> {
        let len = self.u16()?;
        if len == 0xffff {
            return Some(None);
        }
        String::from_utf8(self.take(usize::from(len))?.to_vec())
            .ok()
            .map(Some)
    }
    fn ip(&mut self) -> Option<IpAddr> {
        match self.u8()? {
            4 => {
                let o: [u8; 4] = self.take(4)?.try_into().ok()?;
                Some(Ipv4Addr::from(o).into())
            }
            6 => {
                let o: [u8; 16] = self.take(16)?.try_into().ok()?;
                Some(Ipv6Addr::from(o).into())
            }
            _ => None,
        }
    }
    fn addr(&mut self) -> Option<SocketAddr> {
        let ip = self.ip()?;
        Some(SocketAddr::new(ip, self.u16()?))
    }
}

/// CRC-32 (IEEE 802.3), bitwise over a small table.
fn crc32(data: &[u8]) -> u32 {
    const TABLE: [u32; 16] = {
        let mut t = [0u32; 16];
        let mut i = 0;
        while i < 16 {
            let mut c = i as u32;
            let mut k = 0;
            while k < 4 {
                c = if c & 1 != 0 {
                    0xedb8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
                k += 1;
            }
            t[i] = c;
            i += 1;
        }
        t
    };
    let mut crc = !0u32;
    for &b in data {
        crc = TABLE[((crc ^ u32::from(b)) & 0x0f) as usize] ^ (crc >> 4);
        crc = TABLE[((crc ^ (u32::from(b) >> 4)) & 0x0f) as usize] ^ (crc >> 4);
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("flynn-spool-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    fn samples() -> Vec<Event> {
        let key = FlowKey {
            protocol: Transport::Tcp,
            src: "10.0.0.2:5000".parse().unwrap(),
            dst: "[2001:db8::1]:443".parse().unwrap(),
        };
        vec![
            Event::FlowOpened {
                id: 1,
                at_ms: 1_760_000_000_000,
                key,
                name: Some("example.com".into()),
                source: NameSource::Dns,
                app: Some(AppId {
                    platform: Platform::Ios,
                    id: "com.example.app".into(),
                    display_name: None,
                }),
                verdict: Verdict::Allow,
            },
            Event::FlowNamed {
                id: 1,
                name: "www.example.com".into(),
                source: NameSource::Sni,
            },
            Event::DnsAnswer {
                at_ms: 5,
                name: "example.com".into(),
                addrs: vec!["1.2.3.4".parse().unwrap(), "::1".parse().unwrap()],
            },
            Event::Sample {
                at_ms: 6,
                mem: MemSample {
                    footprint: 9_000_000,
                    peak_footprint: 11_000_000,
                    cpu_ms: 42,
                },
                stats: StatsSnapshot {
                    packets_in: 10,
                    bytes_down: 4096,
                    ..Default::default()
                },
            },
            Event::FlowClosed {
                id: 1,
                at_ms: 7,
                bytes_up: 517,
                bytes_down: 3000,
                reason: CloseReason::Normal,
            },
        ]
    }

    #[test]
    fn crc32_matches_known_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn round_trips_every_event_kind() {
        let d = dir("roundtrip");
        {
            let mut w = SpoolWriter::open(&d, 1 << 20, 4).unwrap();
            for e in samples() {
                w.append(&e).unwrap();
            }
            w.flush().unwrap();
        }
        assert_eq!(tail(&d, 100).unwrap(), samples());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn torn_tail_keeps_intact_records() {
        let d = dir("torn");
        let path = {
            let mut w = SpoolWriter::open(&d, 1 << 20, 4).unwrap();
            for e in samples() {
                w.append(&e).unwrap();
            }
            w.flush().unwrap();
            segments(&d).unwrap().pop().unwrap().1
        };
        let len = fs::metadata(&path).unwrap().len();
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(len - 3)
            .unwrap();
        let (events, complete) = read_segment(&path).unwrap();
        assert!(!complete);
        assert_eq!(events, samples()[..4].to_vec());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn rotates_and_prunes_oldest_segments() {
        let d = dir("rotate");
        {
            let mut w = SpoolWriter::open(&d, 4096, 3).unwrap();
            for i in 0..2000 {
                w.append(&Event::FlowNamed {
                    id: i,
                    name: "x".repeat(20),
                    source: NameSource::Sni,
                })
                .unwrap();
            }
            w.flush().unwrap();
        }
        let segs = segments(&d).unwrap();
        assert_eq!(segs.len(), 3, "kept {:?}", segs);
        // The newest events survive; the oldest were pruned.
        let events = tail(&d, 10_000).unwrap();
        assert!(matches!(
            events.last(),
            Some(Event::FlowNamed { id: 1999, .. })
        ));
        assert!(!matches!(
            events.first(),
            Some(Event::FlowNamed { id: 0, .. })
        ));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn reopening_starts_a_new_segment() {
        let d = dir("reopen");
        SpoolWriter::open(&d, 1 << 20, 4)
            .unwrap()
            .append(&samples()[1])
            .unwrap();
        let mut w = SpoolWriter::open(&d, 1 << 20, 4).unwrap();
        w.append(&samples()[1]).unwrap();
        w.flush().unwrap();
        assert_eq!(segments(&d).unwrap().len(), 2);
        assert_eq!(tail(&d, 10).unwrap().len(), 2);
        let _ = fs::remove_dir_all(&d);
    }
}
