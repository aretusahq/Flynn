//! DNS messages, enough to learn which names resolve to which addresses.
//!
//! Only questions and A, AAAA and CNAME answers are decoded; every other
//! record is skipped. Names are decompressed with a jump limit, so a
//! malicious pointer loop ends in an error rather than a hang.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_HTTPS: u16 = 65;

/// Longest presentation-format name accepted (RFC 1035 limit).
const MAX_NAME_LEN: usize = 253;
/// Compression pointers followed per name before giving up.
const MAX_JUMPS: usize = 16;
/// Records decoded per section; the rest of a huge message is ignored.
const MAX_RECORDS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub is_response: bool,
    /// Response code (0 = NOERROR, 3 = NXDOMAIN).
    pub rcode: u8,
    pub questions: Vec<Question>,
    pub answers: Vec<Answer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub name: String,
    pub ttl: u32,
    pub data: AnswerData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnswerData {
    Address(IpAddr),
    Cname(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsError {
    Truncated,
    BadName,
}

pub fn parse(msg: &[u8]) -> Result<Message, DnsError> {
    if msg.len() < 12 {
        return Err(DnsError::Truncated);
    }
    let id = u16::from_be_bytes([msg[0], msg[1]]);
    let is_response = msg[2] & 0x80 != 0;
    let rcode = msg[3] & 0x0f;
    let qdcount = usize::from(u16::from_be_bytes([msg[4], msg[5]]));
    let ancount = usize::from(u16::from_be_bytes([msg[6], msg[7]]));

    let mut at = 12;
    let mut questions = Vec::new();
    for _ in 0..qdcount.min(MAX_RECORDS) {
        let (name, next) = read_name(msg, at)?;
        let fixed = msg.get(next..next + 4).ok_or(DnsError::Truncated)?;
        questions.push(Question {
            name,
            qtype: u16::from_be_bytes([fixed[0], fixed[1]]),
        });
        at = next + 4;
    }
    if qdcount > MAX_RECORDS {
        // The answers can't be located without walking every question.
        return Ok(Message {
            id,
            is_response,
            rcode,
            questions,
            answers: Vec::new(),
        });
    }

    let mut answers = Vec::new();
    for _ in 0..ancount.min(MAX_RECORDS) {
        let (name, next) = read_name(msg, at)?;
        let fixed = msg.get(next..next + 10).ok_or(DnsError::Truncated)?;
        let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
        let ttl = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
        let rdlen = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        let rdata_at = next + 10;
        let rdata = msg
            .get(rdata_at..rdata_at + rdlen)
            .ok_or(DnsError::Truncated)?;
        let data = match (rtype, rdlen) {
            (TYPE_A, 4) => Some(AnswerData::Address(
                Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).into(),
            )),
            (TYPE_AAAA, 16) => {
                let octets = <[u8; 16]>::try_from(rdata).map_err(|_| DnsError::Truncated)?;
                Some(AnswerData::Address(Ipv6Addr::from(octets).into()))
            }
            (TYPE_CNAME, _) => Some(AnswerData::Cname(read_name(msg, rdata_at)?.0)),
            _ => None,
        };
        if let Some(data) = data {
            answers.push(Answer { name, ttl, data });
        }
        at = rdata_at + rdlen;
    }
    Ok(Message {
        id,
        is_response,
        rcode,
        questions,
        answers,
    })
}

/// Reads a possibly compressed name starting at `at`. Returns the name in
/// lowercase dotted form (no trailing dot; the root is "") and the offset
/// just past the name in the original position.
fn read_name(msg: &[u8], mut at: usize) -> Result<(String, usize), DnsError> {
    let mut name = String::new();
    let mut end_of_name = None;
    let mut jumps = 0;
    loop {
        let len = *msg.get(at).ok_or(DnsError::Truncated)?;
        match len & 0xc0 {
            0x00 => {
                if len == 0 {
                    let next = end_of_name.unwrap_or(at + 1);
                    return Ok((name, next));
                }
                let label = msg
                    .get(at + 1..at + 1 + usize::from(len))
                    .ok_or(DnsError::Truncated)?;
                if !name.is_empty() {
                    name.push('.');
                }
                for &b in label {
                    // Keep names printable; anything else marks a bad name.
                    if !(b.is_ascii_graphic()) || b == b'.' {
                        return Err(DnsError::BadName);
                    }
                    name.push(char::from(b.to_ascii_lowercase()));
                }
                if name.len() > MAX_NAME_LEN {
                    return Err(DnsError::BadName);
                }
                at += 1 + usize::from(len);
            }
            0xc0 => {
                let low = *msg.get(at + 1).ok_or(DnsError::Truncated)?;
                if end_of_name.is_none() {
                    end_of_name = Some(at + 2);
                }
                jumps += 1;
                if jumps > MAX_JUMPS {
                    return Err(DnsError::BadName);
                }
                at = usize::from(u16::from_be_bytes([len & 0x3f, low]));
            }
            _ => return Err(DnsError::BadName),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build;

    #[test]
    fn parses_query() {
        let q = build::dns_query(0x1234, "Example.COM", TYPE_A);
        let m = parse(&q).unwrap();
        assert_eq!(m.id, 0x1234);
        assert!(!m.is_response);
        assert_eq!(
            m.questions,
            vec![Question {
                name: "example.com".into(),
                qtype: TYPE_A
            }]
        );
    }

    #[test]
    fn parses_compressed_answers_with_cname() {
        let r = build::dns_response(
            7,
            "www.example.com",
            &[
                build::DnsRecord::Cname("cdn.example.net"),
                build::DnsRecord::A([93, 184, 216, 34]),
                build::DnsRecord::Aaaa("2606:2800:220:1::".parse().unwrap()),
            ],
        );
        let m = parse(&r).unwrap();
        assert!(m.is_response);
        assert_eq!(m.answers.len(), 3);
        assert_eq!(
            m.answers[0].data,
            AnswerData::Cname("cdn.example.net".into())
        );
        // Records after the CNAME are owned by its target.
        assert_eq!(m.answers[0].name, "www.example.com");
        assert_eq!(m.answers[1].name, "cdn.example.net");
        assert_eq!(
            m.answers[1].data,
            AnswerData::Address("93.184.216.34".parse().unwrap())
        );
        assert_eq!(
            m.answers[2].data,
            AnswerData::Address("2606:2800:220:1::".parse().unwrap())
        );
    }

    #[test]
    fn pointer_loop_is_an_error() {
        let mut m = vec![0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]); // name points at itself
        assert_eq!(parse(&m), Err(DnsError::BadName));
    }

    #[test]
    fn truncated_answer_is_an_error() {
        let mut r = build::dns_response(1, "a.example", &[build::DnsRecord::A([1, 2, 3, 4])]);
        r.truncate(r.len() - 2);
        assert_eq!(parse(&r), Err(DnsError::Truncated));
    }
}
