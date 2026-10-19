//! Parsers for the packets the data plane reads.
//!
//! Every input here is hostile: it arrives from any app and any server.
//! Parsers take borrowed slices, never panic and allocate nothing on the hot
//! path. Each parser gets a fuzz target in `core/fuzz` (M1).

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_version_nibble() {
        assert_eq!(ip_version(&[0x45, 0x00]), Some(IpVersion::V4));
        assert_eq!(ip_version(&[0x60, 0x00]), Some(IpVersion::V6));
        assert_eq!(ip_version(&[0x00]), None);
        assert_eq!(ip_version(&[]), None);
    }
}
