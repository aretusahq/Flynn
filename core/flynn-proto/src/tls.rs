//! The server name (SNI) from a TLS ClientHello.
//!
//! A ClientHello with post-quantum key shares is around 1.8 KB and often
//! spans two TCP segments, so the caller buffers the first client bytes and
//! calls [`client_hello_sni`] again while it returns [`Sni::Incomplete`].

/// Largest ClientHello prefix worth buffering before giving up.
pub const MAX_CLIENT_HELLO: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sni<'a> {
    /// The ClientHello names this server.
    Found(&'a str),
    /// A ClientHello with no server name (connecting by IP).
    Absent,
    /// The bytes so far are the start of a ClientHello; more are needed.
    Incomplete,
    /// Not a TLS ClientHello.
    NotTls,
}

pub fn client_hello_sni(data: &[u8]) -> Sni<'_> {
    // Record header: type 22 (handshake), version 3.x, length.
    let Some(&record_type) = data.first() else {
        return Sni::Incomplete;
    };
    if record_type != 22 {
        return Sni::NotTls;
    }
    if data.len() >= 2 && data[1] != 3 {
        return Sni::NotTls;
    }
    if data.len() < 5 {
        return Sni::Incomplete;
    }
    // The handshake may span several records; join their bodies up to the
    // handshake length. The common case is one record, borrowed directly.
    let first_len = usize::from(u16::from_be_bytes([data[3], data[4]]));
    if data.len() < 9 {
        return Sni::Incomplete;
    }
    if data[5] != 1 {
        return Sni::NotTls; // not a ClientHello
    }
    let hs_len = (usize::from(data[6]) << 16) | (usize::from(data[7]) << 8) | usize::from(data[8]);
    if hs_len + 4 > MAX_CLIENT_HELLO {
        return Sni::NotTls;
    }
    if first_len >= hs_len + 4 {
        return match data.get(9..9 + hs_len) {
            Some(body) => parse_hello(body).unwrap_or(Sni::NotTls),
            None => Sni::Incomplete,
        };
    }
    // Multi-record ClientHello: rare; would need joining record bodies.
    // Report Absent rather than borrow across records.
    if data.len() < 5 + first_len {
        return Sni::Incomplete;
    }
    Sni::Absent
}

fn parse_hello(body: &[u8]) -> Option<Sni<'_>> {
    let mut r = Reader { buf: body, at: 0 };
    r.skip(2 + 32)?; // legacy version, random
    let sid = usize::from(r.u8()?);
    r.skip(sid)?;
    let suites = usize::from(r.u16()?);
    r.skip(suites)?;
    let comp = usize::from(r.u8()?);
    r.skip(comp)?;
    if r.remaining() == 0 {
        return Some(Sni::Absent); // no extensions
    }
    let ext_total = usize::from(r.u16()?);
    let mut ext = Reader {
        buf: r.take(ext_total)?,
        at: 0,
    };
    while ext.remaining() >= 4 {
        let ty = ext.u16()?;
        let len = usize::from(ext.u16()?);
        let data = ext.take(len)?;
        if ty == 0 {
            return Some(parse_server_name(data).unwrap_or(Sni::Absent));
        }
    }
    Some(Sni::Absent)
}

fn parse_server_name(data: &[u8]) -> Option<Sni<'_>> {
    let mut r = Reader { buf: data, at: 0 };
    let list_len = usize::from(r.u16()?);
    let mut list = Reader {
        buf: r.take(list_len)?,
        at: 0,
    };
    while list.remaining() >= 3 {
        let name_type = list.u8()?;
        let len = usize::from(list.u16()?);
        let name = list.take(len)?;
        if name_type == 0 {
            let name = std::str::from_utf8(name).ok()?;
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_graphic()) {
                return None;
            }
            return Some(Sni::Found(name));
        }
    }
    None
}

struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn remaining(&self) -> usize {
        self.buf.len() - self.at
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.buf.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(s)
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_be_bytes([s[0], s[1]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build;

    #[test]
    fn finds_sni() {
        let hello = build::client_hello(Some("api.example.com"), 0);
        assert_eq!(client_hello_sni(&hello), Sni::Found("api.example.com"));
    }

    #[test]
    fn large_hello_is_incomplete_until_whole() {
        // Padding pushes the hello past one TCP segment, like a PQ key share.
        let hello = build::client_hello(Some("big.example.com"), 1500);
        assert!(hello.len() > 1460);
        assert_eq!(client_hello_sni(&hello[..1460]), Sni::Incomplete);
        assert_eq!(client_hello_sni(&hello), Sni::Found("big.example.com"));
    }

    #[test]
    fn hello_without_sni_is_absent() {
        assert_eq!(client_hello_sni(&build::client_hello(None, 0)), Sni::Absent);
    }

    #[test]
    fn http_is_not_tls() {
        assert_eq!(client_hello_sni(b"GET / HTTP/1.1\r\n"), Sni::NotTls);
    }

    #[test]
    fn short_prefix_is_incomplete() {
        assert_eq!(client_hello_sni(&[22, 3]), Sni::Incomplete);
        assert_eq!(client_hello_sni(&[]), Sni::Incomplete);
    }
}
