//! Names for flows: DNS answers seen in the tunnel, overridden by the TLS
//! server name when one arrives.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use flynn_proto::dns;

/// Where a flow's name came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameSource {
    /// No name seen; the destination is an unknown address.
    None,
    /// A DNS answer seen earlier mapped this address to a name.
    Dns,
    /// The TLS ClientHello named the server.
    Sni,
}

impl NameSource {
    pub fn as_str(self) -> &'static str {
        match self {
            NameSource::None => "none",
            NameSource::Dns => "dns",
            NameSource::Sni => "sni",
        }
    }
}

/// Bounded address-to-name map. Entries are replaced in insertion order once
/// the cap is reached; TTLs are ignored because apps keep using addresses
/// long after their records expire, and a stale name beats none.
pub struct DnsCache {
    cap: usize,
    map: HashMap<IpAddr, (String, u64)>,
    order: VecDeque<(IpAddr, u64)>,
    generation: u64,
}

impl DnsCache {
    pub fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            map: HashMap::new(),
            order: VecDeque::new(),
            generation: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn lookup(&self, addr: &IpAddr) -> Option<&str> {
        self.map.get(addr).map(|(name, _)| name.as_str())
    }

    /// Records every address in a response under the name the app asked for
    /// (the question), not the CNAME target, since that is the name a user
    /// recognises. Returns the name and addresses learned, if any.
    pub fn learn(&mut self, msg: &dns::Message) -> Option<(String, Vec<IpAddr>)> {
        if !msg.is_response {
            return None;
        }
        let asked = msg.questions.first()?.name.clone();
        let addrs: Vec<IpAddr> = msg
            .answers
            .iter()
            .filter_map(|a| match a.data {
                dns::AnswerData::Address(ip) => Some(ip),
                dns::AnswerData::Cname(_) => None,
            })
            .collect();
        for addr in &addrs {
            self.insert(*addr, asked.clone());
        }
        (!addrs.is_empty()).then_some((asked, addrs))
    }

    pub fn insert(&mut self, addr: IpAddr, name: String) {
        self.generation += 1;
        self.map.insert(addr, (name, self.generation));
        self.order.push_back((addr, self.generation));
        while self.map.len() > self.cap {
            let Some((old, generation)) = self.order.pop_front() else {
                break;
            };
            // Skip queue entries superseded by a later insert of the same address.
            if self.map.get(&old).is_some_and(|(_, g)| *g == generation) {
                self.map.remove(&old);
            }
        }
        // Keep the queue from growing without bound under repeated refreshes.
        if self.order.len() > self.cap * 4 {
            let map = &self.map;
            self.order
                .retain(|(addr, generation)| map.get(addr).is_some_and(|(_, g)| g == generation));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flynn_proto::build;

    #[test]
    fn learns_question_name_for_cname_chain() {
        let mut cache = DnsCache::new(16);
        let msg = dns::parse(&build::dns_response(
            1,
            "www.example.com",
            &[
                build::DnsRecord::Cname("edge.cdn.net"),
                build::DnsRecord::A([1, 2, 3, 4]),
            ],
        ))
        .unwrap();
        let (name, addrs) = cache.learn(&msg).unwrap();
        assert_eq!(name, "www.example.com");
        assert_eq!(addrs, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
        assert_eq!(
            cache.lookup(&"1.2.3.4".parse().unwrap()),
            Some("www.example.com")
        );
    }

    #[test]
    fn evicts_oldest_at_cap() {
        let mut cache = DnsCache::new(2);
        let a: IpAddr = "1.1.1.1".parse().unwrap();
        let b: IpAddr = "2.2.2.2".parse().unwrap();
        let c: IpAddr = "3.3.3.3".parse().unwrap();
        cache.insert(a, "a".into());
        cache.insert(b, "b".into());
        cache.insert(a, "a2".into()); // refresh a
        cache.insert(c, "c".into()); // evicts b, the oldest live entry
        assert_eq!(cache.lookup(&a), Some("a2"));
        assert_eq!(cache.lookup(&b), None);
        assert_eq!(cache.lookup(&c), Some("c"));
    }
}
