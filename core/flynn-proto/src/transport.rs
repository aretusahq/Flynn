//! TCP and UDP headers.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSegment<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlags(pub u8);

impl TcpFlags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const ACK: u8 = 0x10;

    pub fn syn(self) -> bool {
        self.0 & Self::SYN != 0
    }
    pub fn ack(self) -> bool {
        self.0 & Self::ACK != 0
    }
    pub fn fin(self) -> bool {
        self.0 & Self::FIN != 0
    }
    pub fn rst(self) -> bool {
        self.0 & Self::RST != 0
    }
    /// A connection-opening SYN (not a SYN-ACK).
    pub fn is_initial_syn(self) -> bool {
        self.syn() && !self.ack()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpDatagram<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    Truncated,
    BadHeader,
}

pub fn parse_tcp(segment: &[u8]) -> Result<TcpSegment<'_>, TransportError> {
    if segment.len() < 20 {
        return Err(TransportError::Truncated);
    }
    let offset = usize::from(segment[12] >> 4) * 4;
    if offset < 20 {
        return Err(TransportError::BadHeader);
    }
    let payload = segment.get(offset..).ok_or(TransportError::Truncated)?;
    Ok(TcpSegment {
        src_port: u16::from_be_bytes([segment[0], segment[1]]),
        dst_port: u16::from_be_bytes([segment[2], segment[3]]),
        seq: u32::from_be_bytes([segment[4], segment[5], segment[6], segment[7]]),
        ack: u32::from_be_bytes([segment[8], segment[9], segment[10], segment[11]]),
        flags: TcpFlags(segment[13]),
        payload,
    })
}

pub fn parse_udp(datagram: &[u8]) -> Result<UdpDatagram<'_>, TransportError> {
    if datagram.len() < 8 {
        return Err(TransportError::Truncated);
    }
    let len = usize::from(u16::from_be_bytes([datagram[4], datagram[5]]));
    // Length 0 is legal for IPv6 jumbograms; otherwise trust the smaller of
    // the header length and the bytes actually present.
    let end = if len == 0 { datagram.len() } else { len };
    if end < 8 {
        return Err(TransportError::BadHeader);
    }
    let payload = datagram.get(8..end).ok_or(TransportError::Truncated)?;
    Ok(UdpDatagram {
        src_port: u16::from_be_bytes([datagram[0], datagram[1]]),
        dst_port: u16::from_be_bytes([datagram[2], datagram[3]]),
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tcp_syn() {
        let mut s = vec![
            0xc3,
            0x50,
            0x01,
            0xbb,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0x50,
            TcpFlags::SYN,
            0xff,
            0xff,
            0,
            0,
            0,
            0,
        ];
        s.extend_from_slice(b"hi");
        let t = parse_tcp(&s).unwrap();
        assert_eq!((t.src_port, t.dst_port), (50000, 443));
        assert!(t.flags.is_initial_syn());
        assert_eq!(t.payload, b"hi");
    }

    #[test]
    fn rejects_tcp_offset_past_end() {
        let s = [
            0u8, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0xf0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(parse_tcp(&s), Err(TransportError::Truncated));
    }

    #[test]
    fn parses_udp() {
        let d = [0x14, 0xe9, 0, 53, 0, 10, 0, 0, 0xab, 0xcd];
        let u = parse_udp(&d).unwrap();
        assert_eq!((u.src_port, u.dst_port), (5353, 53));
        assert_eq!(u.payload, &[0xab, 0xcd]);
    }
}
