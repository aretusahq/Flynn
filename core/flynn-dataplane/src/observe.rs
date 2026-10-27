//! Passive flow tracking: the same naming and decisions as the forwarder,
//! applied to packets that are only watched, not relayed. Used by pcap
//! replay, so a capture checks parsing, naming, rules and flow accounting
//! without a live network.

use std::collections::HashMap;
use std::sync::Arc;

use flynn_proto::{dns, ip, quic, tls, transport};
use flynn_rules::{NameState, Reason, Verdict};

use crate::names::{DnsCache, NameSource};
use crate::policy::{FlowMeta, Policy, Standing};
use crate::{FlowKey, Transport};

/// One flow as seen in a capture, oriented client to server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowSummary {
    pub key: FlowKey,
    pub name: Option<String>,
    pub source: NameSource,
    /// The final verdict, after the server name (or its absence) settled it.
    pub verdict: Verdict,
    pub reason: Reason,
    pub quic: bool,
    pub packets_up: u64,
    pub packets_down: u64,
    /// Transport payload bytes, client to server.
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub first_ms: i64,
    pub last_ms: i64,
}

pub struct FlowTracker {
    policy: Arc<dyn Policy>,
    names: DnsCache,
    flows: HashMap<FlowKey, Tracked>,
    next_order: usize,
    /// Packets that were not IP, were fragments, or failed to parse.
    pub skipped: u64,
}

struct Tracked {
    order: usize,
    summary: FlowSummary,
    standing: Standing,
    hello: Vec<u8>,
    sniffing: bool,
    /// Reads the server name from a QUIC flow's Initial packets.
    quic: Option<quic::InitialSniffer>,
}

/// Decides again and copies the result into the summary.
fn redecide(policy: &dyn Policy, t: &mut Tracked, name: NameState<'_>) {
    let decision = policy.decide(&FlowMeta {
        key: &t.summary.key,
        name,
        app: None,
    });
    t.standing.update(decision);
    t.summary.verdict = t.standing.verdict;
    t.summary.reason = t.standing.reason;
}

/// No server name is coming: decide with what is known (a name from DNS, or
/// none).
fn settle_without_name(policy: &dyn Policy, t: &mut Tracked) {
    let name = t.summary.name.clone();
    let state = match &name {
        Some(n) => NameState::Known(n),
        None => NameState::Unavailable,
    };
    redecide(policy, t, state);
}

impl FlowTracker {
    pub fn new(policy: Arc<dyn Policy>) -> Self {
        Self {
            policy,
            names: DnsCache::new(4096),
            flows: HashMap::new(),
            next_order: 0,
            skipped: 0,
        }
    }

    pub fn observe(&mut self, at_ms: i64, packet: &[u8]) {
        let Ok(p) = ip::parse(packet) else {
            self.skipped += 1;
            return;
        };
        if p.later_fragment {
            self.skipped += 1;
            return;
        }
        match p.protocol {
            ip::PROTO_TCP => {
                let Ok(t) = transport::parse_tcp(p.payload) else {
                    self.skipped += 1;
                    return;
                };
                let key = FlowKey {
                    protocol: Transport::Tcp,
                    src: (p.src, t.src_port).into(),
                    dst: (p.dst, t.dst_port).into(),
                };
                // A SYN-ACK travels server to client: orient on its reverse.
                let client_first = !(t.flags.syn() && t.flags.ack());
                self.account(at_ms, key, t.payload, client_first);
            }
            ip::PROTO_UDP => {
                let Ok(u) = transport::parse_udp(p.payload) else {
                    self.skipped += 1;
                    return;
                };
                let key = FlowKey {
                    protocol: Transport::Udp,
                    src: (p.src, u.src_port).into(),
                    dst: (p.dst, u.dst_port).into(),
                };
                if u.src_port == 53
                    && let Ok(msg) = dns::parse(u.payload)
                {
                    self.names.learn(&msg);
                }
                self.account(at_ms, key, u.payload, true);
            }
            _ => self.skipped += 1,
        }
    }

    fn account(&mut self, at_ms: i64, key: FlowKey, payload: &[u8], client_first: bool) {
        let reverse = FlowKey {
            protocol: key.protocol,
            src: key.dst,
            dst: key.src,
        };
        let (flow_key, up) = if self.flows.contains_key(&key) {
            (key, true)
        } else if self.flows.contains_key(&reverse) {
            (reverse, false)
        } else if client_first {
            (key, true)
        } else {
            (reverse, false)
        };

        if !self.flows.contains_key(&flow_key) {
            let name = self.names.lookup(&flow_key.dst.ip()).map(str::to_owned);
            // A name may still come: from a ClientHello over TCP, or from a
            // QUIC Initial.
            let can_name = flow_key.protocol == Transport::Tcp
                || (flow_key.dst.port() == 443 && quic::initial_version(payload).is_some());
            let state = match &name {
                Some(n) => NameState::Known(n),
                None if can_name => NameState::Pending,
                None => NameState::Unavailable,
            };
            let decision = self.policy.decide(&FlowMeta {
                key: &flow_key,
                name: state,
                app: None,
            });
            let standing = Standing::from_decision(decision);
            let order = self.next_order;
            self.next_order += 1;
            self.flows.insert(
                flow_key,
                Tracked {
                    order,
                    summary: FlowSummary {
                        key: flow_key,
                        source: if name.is_some() {
                            NameSource::Dns
                        } else {
                            NameSource::None
                        },
                        name,
                        verdict: standing.verdict,
                        reason: standing.reason,
                        quic: false,
                        packets_up: 0,
                        packets_down: 0,
                        bytes_up: 0,
                        bytes_down: 0,
                        first_ms: at_ms,
                        last_ms: at_ms,
                    },
                    standing,
                    hello: Vec::new(),
                    sniffing: flow_key.protocol == Transport::Tcp,
                    quic: None,
                },
            );
        }

        let policy = self.policy.clone();
        let Some(flow) = self.flows.get_mut(&flow_key) else {
            return;
        };
        flow.summary.last_ms = at_ms;
        if up {
            flow.summary.packets_up += 1;
            flow.summary.bytes_up += payload.len() as u64;
        } else {
            flow.summary.packets_down += 1;
            flow.summary.bytes_down += payload.len() as u64;
        }

        if up && !payload.is_empty() {
            if flow.summary.key.protocol == Transport::Udp
                && flow.summary.key.dst.port() == 443
                && quic::initial_version(payload).is_some()
            {
                if !flow.summary.quic {
                    flow.quic = Some(quic::InitialSniffer::new());
                }
                flow.summary.quic = true;
            }
            let mut found: Option<String> = None;
            let mut gave_up = false;
            if let Some(sniffer) = flow.quic.as_mut() {
                match sniffer.feed(payload) {
                    quic::QuicSni::Incomplete => {}
                    quic::QuicSni::Found(name) => {
                        found = Some(name);
                        flow.quic = None;
                    }
                    _ => {
                        gave_up = true;
                        flow.quic = None;
                    }
                }
            }
            if flow.sniffing {
                flow.hello.extend_from_slice(payload);
                match tls::client_hello_sni(&flow.hello) {
                    tls::Sni::Incomplete if flow.hello.len() < tls::MAX_CLIENT_HELLO => {}
                    tls::Sni::Found(name) => {
                        found = Some(name.to_ascii_lowercase());
                        flow.sniffing = false;
                        flow.hello = Vec::new();
                    }
                    _ => {
                        gave_up = true;
                        flow.sniffing = false;
                        flow.hello = Vec::new();
                    }
                }
            }
            if let Some(name) = found {
                flow.summary.name = Some(name.clone());
                flow.summary.source = NameSource::Sni;
                redecide(&*policy, flow, NameState::Known(&name));
            } else if gave_up {
                settle_without_name(&*policy, flow);
            }
        }
    }

    /// Flows in the order they were first seen. Any still waiting for a name
    /// that never came are settled without one.
    pub fn finish(self) -> Vec<FlowSummary> {
        let policy = self.policy.clone();
        let mut flows: Vec<Tracked> = self.flows.into_values().collect();
        flows.sort_by_key(|f| f.order);
        for f in &mut flows {
            if f.standing.awaiting_name {
                settle_without_name(&*policy, f);
            }
        }
        flows.into_iter().map(|f| f.summary).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::RulesPolicy;
    use flynn_proto::build;
    use flynn_proto::transport::TcpFlags;
    use flynn_rules::Mode;
    use std::net::SocketAddr;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn allow_all() -> Arc<dyn Policy> {
        Arc::new(RulesPolicy::allow_all())
    }

    #[test]
    fn names_tcp_flow_from_dns_then_sni_and_counts_both_ways() {
        let mut t = FlowTracker::new(allow_all());
        let (client, resolver, server) = (
            addr("10.0.0.2:5353"),
            addr("10.0.0.1:53"),
            addr("93.184.216.34:443"),
        );
        t.observe(
            0,
            &build::udp_packet(
                client,
                resolver,
                &build::dns_query(1, "example.com", dns::TYPE_A),
            ),
        );
        t.observe(
            1,
            &build::udp_packet(
                resolver,
                client,
                &build::dns_response(1, "example.com", &[build::DnsRecord::A([93, 184, 216, 34])]),
            ),
        );
        let app = addr("10.0.0.2:50000");
        t.observe(2, &build::tcp_packet(app, server, 1, 0, TcpFlags::SYN, &[]));
        t.observe(
            3,
            &build::tcp_packet(server, app, 9, 2, TcpFlags::SYN | TcpFlags::ACK, &[]),
        );
        t.observe(
            4,
            &build::tcp_packet(
                app,
                server,
                2,
                10,
                TcpFlags::ACK,
                &build::client_hello(Some("www.example.com"), 0),
            ),
        );
        t.observe(
            5,
            &build::tcp_packet(server, app, 10, 3, TcpFlags::ACK, &[0u8; 100]),
        );
        let flows = t.finish();
        assert_eq!(flows.len(), 2);
        let tcp = &flows[1];
        assert_eq!(tcp.key.src, app);
        assert_eq!(tcp.name.as_deref(), Some("www.example.com"));
        assert_eq!(tcp.source, NameSource::Sni);
        assert_eq!((tcp.packets_up, tcp.packets_down), (2, 2));
        assert_eq!(tcp.bytes_down, 100);
        assert_eq!(
            (tcp.verdict, tcp.reason),
            (Verdict::Allow, Reason::ModeDefault)
        );
    }

    #[test]
    fn sni_can_block_a_flow_dns_allowed() {
        let mut t = FlowTracker::new(Arc::new(RulesPolicy::blocking_domains(["ads.example"])));
        let (app, server) = (addr("10.0.0.2:50000"), addr("1.2.3.4:443"));
        t.observe(0, &build::tcp_packet(app, server, 1, 0, TcpFlags::SYN, &[]));
        t.observe(
            1,
            &build::tcp_packet(
                app,
                server,
                2,
                0,
                TcpFlags::ACK,
                &build::client_hello(Some("x.ads.example"), 0),
            ),
        );
        let flows = t.finish();
        assert_eq!(flows[0].verdict, Verdict::Block);
        // Rule 2 is the subdomains rule that blocking_domains adds.
        assert_eq!(flows[0].reason, Reason::Rule { id: 2 });
    }

    #[test]
    fn flags_quic_initial() {
        let mut t = FlowTracker::new(allow_all());
        t.observe(
            0,
            &build::udp_packet(
                addr("10.0.0.2:60000"),
                addr("1.2.3.4:443"),
                &[0xc3, 0, 0, 0, 1, 8, 0, 0],
            ),
        );
        assert!(t.finish()[0].quic);
    }

    #[test]
    fn block_all_waits_for_the_name_then_applies_the_rules() {
        use flynn_rules::{Action, Config, Dest, Rule};
        let config = Config {
            mode: Mode::BlockAll,
            panic: false,
            essentials: true,
            rules: vec![Rule {
                id: 7,
                action: Action::Allow,
                dest: Dest::Domain("www.example.com".into()),
                app: None,
                ports: None,
                transport: None,
            }],
        };
        let mut t = FlowTracker::new(Arc::new(RulesPolicy::from_config(&config).unwrap()));
        let server = addr("93.184.216.34:443");
        // A flow whose ClientHello names the allowed site.
        let named = addr("10.0.0.2:50000");
        t.observe(
            0,
            &build::tcp_packet(named, server, 1, 0, TcpFlags::SYN, &[]),
        );
        t.observe(
            1,
            &build::tcp_packet(
                named,
                server,
                2,
                0,
                TcpFlags::ACK,
                &build::client_hello(Some("www.example.com"), 0),
            ),
        );
        // A flow that never sends a ClientHello: no name ever comes.
        let silent = addr("10.0.0.2:50001");
        t.observe(
            2,
            &build::tcp_packet(silent, server, 1, 0, TcpFlags::SYN, &[]),
        );
        // DNS is essential, whatever the name.
        t.observe(
            3,
            &build::udp_packet(addr("10.0.0.2:5000"), addr("10.0.0.1:53"), &[0; 12]),
        );
        let flows = t.finish();
        assert_eq!(
            (flows[0].verdict, flows[0].reason),
            (Verdict::Allow, Reason::Rule { id: 7 })
        );
        assert_eq!(
            (flows[1].verdict, flows[1].reason),
            (Verdict::Block, Reason::ModeDefault)
        );
        assert_eq!(
            (flows[2].verdict, flows[2].reason),
            (Verdict::Allow, Reason::Essential)
        );
    }
}
