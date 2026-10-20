//! QUIC: recognising Initial packets and reading the server name from them.
//!
//! A QUIC client's first packets carry its TLS ClientHello in CRYPTO frames,
//! encrypted with keys anyone can derive from the destination connection ID
//! (RFC 9001 §5.2; RFC 9369 for v2). Reading the name means: derive the
//! client Initial keys, remove header protection, decrypt with AES-128-GCM,
//! and reassemble CRYPTO frames, which modern stacks split across several
//! packets and datagrams (a post-quantum key share does not fit in one) and
//! may send out of order.

use aes::Aes128;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes_gcm::aead::AeadInOut;
use aes_gcm::{Aes128Gcm, Nonce, Tag};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::tls;

pub const VERSION_1: u32 = 1;
pub const VERSION_2: u32 = 0x6b33_43cf;

const SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

/// Largest ClientHello the sniffer reassembles.
const MAX_CRYPTO: usize = tls::MAX_CLIENT_HELLO;
/// Initial packets examined per flow before giving up.
const MAX_PACKETS: u32 = 8;

/// If `payload` is a QUIC long-header Initial packet, returns its version.
pub fn initial_version(payload: &[u8]) -> Option<u32> {
    let first = *payload.first()?;
    // Long header (bit 7) with the fixed bit (bit 6) set.
    if first & 0xc0 != 0xc0 {
        return None;
    }
    let version = u32::from_be_bytes(payload.get(1..5)?.try_into().ok()?);
    is_initial(first, version).then_some(version)
}

fn is_initial(first: u8, version: u32) -> bool {
    let packet_type = (first >> 4) & 0x03;
    match version {
        VERSION_1 => packet_type == 0,
        VERSION_2 => packet_type == 1, // QUIC v2 renumbers Initial to 1
        _ => false,
    }
}

/// Client Initial packet protection keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialKeys {
    pub key: [u8; 16],
    pub iv: [u8; 12],
    pub hp: [u8; 16],
}

/// Derives the client's Initial keys from the destination connection ID.
pub fn client_initial_keys(version: u32, dcid: &[u8]) -> Option<InitialKeys> {
    let (salt, key_label, iv_label, hp_label) = match version {
        VERSION_1 => (&SALT_V1, "quic key", "quic iv", "quic hp"),
        VERSION_2 => (&SALT_V2, "quicv2 key", "quicv2 iv", "quicv2 hp"),
        _ => return None,
    };
    let (initial_secret, _) = Hkdf::<Sha256>::extract(Some(salt), dcid);
    let mut client_secret = [0u8; 32];
    expand_label(&initial_secret, "client in", &mut client_secret)?;
    let mut keys = InitialKeys {
        key: [0; 16],
        iv: [0; 12],
        hp: [0; 16],
    };
    expand_label(&client_secret, key_label, &mut keys.key)?;
    expand_label(&client_secret, iv_label, &mut keys.iv)?;
    expand_label(&client_secret, hp_label, &mut keys.hp)?;
    Some(keys)
}

/// TLS 1.3 HKDF-Expand-Label with an empty context.
fn expand_label(secret: &[u8], label: &str, out: &mut [u8]) -> Option<()> {
    let hk = Hkdf::<Sha256>::from_prk(secret).ok()?;
    let full = [b"tls13 ", label.as_bytes()].concat();
    let mut info = Vec::with_capacity(4 + full.len());
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(&full);
    info.push(0); // empty context
    hk.expand(&info, out).ok()
}

/// The header-protection mask for a 16-byte sample.
pub fn header_mask(hp: &[u8; 16], sample: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(&(*hp).into());
    let mut block = (*sample).into();
    cipher.encrypt_block(&mut block);
    block.into()
}

/// Result of feeding datagrams to an [`InitialSniffer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicSni {
    /// The ClientHello names this server.
    Found(String),
    /// A complete ClientHello with no server name.
    Absent,
    /// More Initial packets are needed.
    Incomplete,
    /// Not a decryptable client Initial, or not a ClientHello: stop trying.
    Failed,
}

/// Reads the server name from a flow's first client datagrams.
#[derive(Default)]
pub struct InitialSniffer {
    keys: Option<(u32, InitialKeys)>,
    /// Reassembly buffer for CRYPTO frame data, and the byte ranges filled.
    crypto: Vec<u8>,
    ranges: Vec<(usize, usize)>,
    packets: u32,
}

impl InitialSniffer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds one client datagram, which may hold several coalesced packets.
    pub fn feed(&mut self, datagram: &[u8]) -> QuicSni {
        let mut at = 0;
        while at < datagram.len() {
            match self.open_packet(&datagram[at..]) {
                Some((consumed, Some(plaintext))) => {
                    self.packets += 1;
                    if !self.collect_crypto(&plaintext) {
                        return QuicSni::Failed;
                    }
                    at += consumed;
                }
                // A long-header packet of another type (0-RTT): skip it.
                Some((consumed, None)) => at += consumed,
                None => break,
            }
            if self.packets > MAX_PACKETS {
                return QuicSni::Failed;
            }
        }
        if self.packets == 0 {
            return QuicSni::Failed;
        }
        self.try_name()
    }

    /// Parses and decrypts one packet. Returns the bytes it occupies, and the
    /// plaintext if it was a client Initial. None when no packet can be
    /// parsed here (short header, garbage, padding).
    fn open_packet(&mut self, p: &[u8]) -> Option<(usize, Option<Vec<u8>>)> {
        let first = *p.first()?;
        if first & 0x80 == 0 {
            return None;
        }
        let version = u32::from_be_bytes(p.get(1..5)?.try_into().ok()?);
        let dcid_len = usize::from(*p.get(5)?);
        if dcid_len > 20 {
            return None;
        }
        let dcid = p.get(6..6 + dcid_len)?;
        let mut at = 6 + dcid_len;
        let scid_len = usize::from(*p.get(at)?);
        at += 1 + scid_len;
        let initial = is_initial(first, version);
        if initial {
            let (token_len, n) = varint(p.get(at..)?)?;
            at += n + usize::try_from(token_len).ok()?;
        } else if (first >> 4) & 0x03 == 3 && version == VERSION_1 {
            return None; // Retry: no length field
        }
        let (length, n) = varint(p.get(at..)?)?;
        at += n;
        let length = usize::try_from(length).ok()?;
        let pn_offset = at;
        let end = pn_offset.checked_add(length)?;
        if end > p.len() {
            return None;
        }
        if !initial {
            return Some((end, None));
        }

        // The first Initial fixes the keys: later client Initials keep the
        // original destination connection ID.
        if self.keys.is_none() {
            self.keys = Some((version, client_initial_keys(version, dcid)?));
        }
        let (key_version, keys) = self.keys.as_ref()?;
        if *key_version != version {
            return None;
        }

        let sample: [u8; 16] = p.get(pn_offset + 4..pn_offset + 20)?.try_into().ok()?;
        let mask = header_mask(&keys.hp, &sample);
        let first_plain = first ^ (mask[0] & 0x0f);
        let pn_len = usize::from(first_plain & 0x03) + 1;
        if length < pn_len + 16 {
            return None;
        }
        let mut header = p[..pn_offset + pn_len].to_vec();
        header[0] = first_plain;
        let mut pn: u64 = 0;
        for i in 0..pn_len {
            header[pn_offset + i] ^= mask[1 + i];
            pn = (pn << 8) | u64::from(header[pn_offset + i]);
        }

        let mut nonce = keys.iv;
        for (i, b) in pn.to_be_bytes().iter().enumerate() {
            nonce[4 + i] ^= b;
        }
        let body = &p[pn_offset + pn_len..end];
        let (ciphertext, tag) = body.split_at(body.len() - 16);
        let mut plaintext = ciphertext.to_vec();
        let cipher = Aes128Gcm::new(&keys.key.into());
        let tag = Tag::try_from(tag).ok()?;
        cipher
            .decrypt_inout_detached(
                &Nonce::from(nonce),
                &header,
                plaintext.as_mut_slice().into(),
                &tag,
            )
            .ok()?;
        Some((end, Some(plaintext)))
    }

    /// Copies CRYPTO frame data into the reassembly buffer. False if the
    /// payload holds a frame a client Initial cannot carry.
    fn collect_crypto(&mut self, payload: &[u8]) -> bool {
        let mut r = payload;
        while let Some(&ty) = r.first() {
            match ty {
                0x00 | 0x01 => r = &r[1..], // PADDING, PING
                0x02 | 0x03 => {
                    // ACK: largest, delay, range count, first range, ranges, (ECN).
                    let Some(rest) = skip_ack(&r[1..], ty == 0x03) else {
                        return false;
                    };
                    r = rest;
                }
                0x06 => {
                    let Some((offset, n1)) = varint(&r[1..]) else {
                        return false;
                    };
                    let Some((len, n2)) = varint(&r[1 + n1..]) else {
                        return false;
                    };
                    let start = 1 + n1 + n2;
                    let (Ok(offset), Ok(len)) = (usize::try_from(offset), usize::try_from(len))
                    else {
                        return false;
                    };
                    let Some(data) = r.get(start..start + len) else {
                        return false;
                    };
                    self.insert(offset, data);
                    r = &r[start + len..];
                }
                0x1c | 0x1d => return true, // CONNECTION_CLOSE
                _ => return false,
            }
        }
        true
    }

    fn insert(&mut self, offset: usize, data: &[u8]) {
        let end = offset.saturating_add(data.len());
        if end > MAX_CRYPTO || data.is_empty() {
            return;
        }
        if self.crypto.len() < end {
            self.crypto.resize(end, 0);
        }
        self.crypto[offset..end].copy_from_slice(data);
        self.ranges.push((offset, end));
        self.ranges.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(self.ranges.len());
        for &(s, e) in &self.ranges {
            match merged.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => merged.push((s, e)),
            }
        }
        self.ranges = merged;
    }

    fn try_name(&self) -> QuicSni {
        let contiguous = match self.ranges.first() {
            Some(&(0, end)) => end,
            _ => return QuicSni::Incomplete,
        };
        match tls::handshake_sni(&self.crypto[..contiguous]) {
            tls::Sni::Found(name) => QuicSni::Found(name.to_ascii_lowercase()),
            tls::Sni::Absent => QuicSni::Absent,
            tls::Sni::Incomplete => QuicSni::Incomplete,
            tls::Sni::NotTls => QuicSni::Failed,
        }
    }
}

fn skip_ack(r: &[u8], ecn: bool) -> Option<&[u8]> {
    let mut at = 0;
    let next = |r: &[u8], at: &mut usize| -> Option<u64> {
        let (v, n) = varint(r.get(*at..)?)?;
        *at += n;
        Some(v)
    };
    next(r, &mut at)?; // largest acknowledged
    next(r, &mut at)?; // ack delay
    let ranges = next(r, &mut at)?;
    next(r, &mut at)?; // first range
    for _ in 0..ranges.min(256) {
        next(r, &mut at)?;
        next(r, &mut at)?;
    }
    if ecn {
        for _ in 0..3 {
            next(r, &mut at)?;
        }
    }
    r.get(at..)
}

/// A QUIC variable-length integer: the value and the bytes it used.
pub fn varint(b: &[u8]) -> Option<(u64, usize)> {
    let first = *b.first()?;
    let len = 1usize << (first >> 6);
    let bytes = b.get(..len)?;
    let mut v = u64::from(first & 0x3f);
    for &x in &bytes[1..] {
        v = (v << 8) | u64::from(x);
    }
    Some((v, len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn recognises_v1_initial() {
        assert_eq!(initial_version(&[0xc3, 0, 0, 0, 1, 8]), Some(1));
    }

    #[test]
    fn ignores_short_header_and_handshake() {
        assert_eq!(initial_version(&[0x43, 0, 0, 0, 1]), None);
        assert_eq!(initial_version(&[0xe3, 0, 0, 0, 1]), None); // handshake type
    }

    /// RFC 9001 Appendix A.1 and A.2.
    #[test]
    fn v1_keys_and_mask_match_rfc_9001() {
        let keys = client_initial_keys(VERSION_1, &hex("8394c8f03e515708")).unwrap();
        assert_eq!(keys.key.to_vec(), hex("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(keys.iv.to_vec(), hex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(keys.hp.to_vec(), hex("9f50449e04a0e810283a1e9933adedd2"));
        let sample: [u8; 16] = hex("d1b1c98dd7689fb8ec11d242b123dc9b").try_into().unwrap();
        assert_eq!(
            header_mask(&keys.hp, &sample)[..5].to_vec(),
            hex("437b9aec36")
        );
    }

    #[test]
    fn varints_decode() {
        assert_eq!(varint(&[0x25]), Some((37, 1)));
        assert_eq!(varint(&[0x7b, 0xbd]), Some((15293, 2)));
        assert_eq!(varint(&[0x9d, 0x7f, 0x3e, 0x7d]), Some((494_878_333, 4)));
        assert_eq!(
            varint(&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]),
            Some((151_288_809_941_952_652, 8))
        );
        assert_eq!(varint(&[0x40]), None);
    }

    /// Real datagrams from Apple's QUIC stack; the ClientHello spans two.
    #[test]
    fn reads_name_from_apple_initials_across_two_datagrams() {
        let d0 = include_bytes!("../../fixtures/quic/apple-initial-0.bin");
        let d1 = include_bytes!("../../fixtures/quic/apple-initial-1.bin");
        let mut s = InitialSniffer::new();
        assert_eq!(s.feed(d0), QuicSni::Incomplete);
        assert_eq!(s.feed(d1), QuicSni::Found("www.flynn-quic.test".into()));
    }

    #[test]
    fn retransmission_alone_is_enough_when_complete_or_incomplete() {
        let d2 = include_bytes!("../../fixtures/quic/apple-initial-2.bin");
        let result = InitialSniffer::new().feed(d2);
        assert!(
            matches!(result, QuicSni::Found(_) | QuicSni::Incomplete),
            "{result:?}"
        );
    }

    #[test]
    fn round_trips_synthetic_initials_v1_and_v2_out_of_order() {
        let hello = build::client_hello(Some("api.example.org"), 2000);
        let handshake = &hello[5..];
        for version in [VERSION_1, VERSION_2] {
            let dgrams = build::quic_initials(version, &[7; 8], handshake, 3);
            assert_eq!(dgrams.len(), 3);
            let mut s = InitialSniffer::new();
            // The builder puts the last fragment first, as Chrome does.
            assert_eq!(s.feed(&dgrams[0]), QuicSni::Incomplete);
            assert_eq!(s.feed(&dgrams[1]), QuicSni::Incomplete);
            assert_eq!(
                s.feed(&dgrams[2]),
                QuicSni::Found("api.example.org".into()),
                "version {version:#x}"
            );
        }
    }

    #[test]
    fn tampered_packet_fails_authentication() {
        let mut d0 = include_bytes!("../../fixtures/quic/apple-initial-0.bin").to_vec();
        let last = d0.len() - 20;
        d0[last] ^= 0xff;
        assert_eq!(InitialSniffer::new().feed(&d0), QuicSni::Failed);
    }

    #[test]
    fn short_header_is_not_an_initial() {
        assert_eq!(InitialSniffer::new().feed(&[0x40; 64]), QuicSni::Failed);
    }
}
