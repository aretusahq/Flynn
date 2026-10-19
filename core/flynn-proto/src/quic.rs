//! QUIC detection.
//!
//! The server name in a QUIC Initial is encrypted with keys derived from the
//! connection ID, so reading it needs HKDF and AES-GCM. That lands in M4;
//! until then a QUIC flow is recognised and named from DNS only.

/// If `payload` is a QUIC long-header Initial packet, returns its version.
pub fn initial_version(payload: &[u8]) -> Option<u32> {
    let first = *payload.first()?;
    // Long header (bit 7) with the fixed bit (bit 6) set.
    if first & 0xc0 != 0xc0 {
        return None;
    }
    let version = u32::from_be_bytes(payload.get(1..5)?.try_into().ok()?);
    let packet_type = (first >> 4) & 0x03;
    let is_initial = match version {
        0 => return None,                // version negotiation
        0x6b33_43cf => packet_type == 1, // QUIC v2 renumbers Initial to 1
        _ => packet_type == 0,
    };
    is_initial.then_some(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_v1_initial() {
        assert_eq!(initial_version(&[0xc3, 0, 0, 0, 1, 8]), Some(1));
    }

    #[test]
    fn ignores_short_header_and_handshake() {
        assert_eq!(initial_version(&[0x43, 0, 0, 0, 1]), None);
        assert_eq!(initial_version(&[0xe3, 0, 0, 0, 1]), None); // handshake type
    }
}
