//! UDP relay: one connected OS socket per flow, replies rebuilt as IP
//! packets addressed back to the app.
//!
//! A QUIC flow's first datagrams are held until the server name has been
//! read from its Initial packets, so the policy decides on the name before
//! anything reaches the server.

use std::io;
use std::time::{Duration, Instant};

use flynn_proto::quic::{InitialSniffer, QuicSni};
use flynn_proto::{build, dns};
use flynn_rules::Verdict;
use flynn_types::AppId;

use crate::FlowKey;
use crate::events::{CloseReason, Event, EventSink, FlowId};
use crate::names::{DnsCache, NameSource};
use crate::policy::{FlowMeta, Policy};

/// Datagrams held per QUIC flow while reading its name.
const MAX_HELD: usize = 6;

pub(crate) struct UdpFlow {
    pub id: FlowId,
    pub key: FlowKey,
    pub socket: mio::net::UdpSocket,
    pub app: Option<AppId>,
    pub last_active: Instant,
    pub is_dns: bool,
    pub answered: bool,
    /// The flow has a name, from DNS at open or from its Initial packets.
    pub named: bool,
    /// Present while the first QUIC datagrams are held for naming.
    pub quic: Option<QuicHold>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub finished: Option<CloseReason>,
}

pub(crate) struct QuicHold {
    sniffer: InitialSniffer,
    started: Instant,
    held: Vec<Vec<u8>>,
}

impl QuicHold {
    pub fn new() -> Self {
        Self {
            sniffer: InitialSniffer::new(),
            started: Instant::now(),
            held: Vec::new(),
        }
    }
}

/// What QUIC naming needs from the forwarder.
pub(crate) struct QuicCtx<'a> {
    pub policy: &'a dyn Policy,
    pub sink: &'a dyn EventSink,
    /// Drop QUIC flows that end up with no name, so the app retries over
    /// TCP, where the TLS server name is visible.
    pub force_tcp_unnamed: bool,
    pub wait: Duration,
}

impl UdpFlow {
    /// App to server. Held while a QUIC flow is being named; otherwise sent.
    pub fn handle_app_datagram(&mut self, payload: &[u8], ctx: &QuicCtx<'_>) {
        self.last_active = Instant::now();
        if self.quic.is_none() {
            self.send(payload);
            return;
        }
        let Some(hold) = self.quic.as_mut() else {
            return;
        };
        hold.held.push(payload.to_vec());
        match hold.sniffer.feed(payload) {
            QuicSni::Found(name) => {
                let verdict = ctx.policy.decide(&FlowMeta {
                    key: &self.key,
                    name: Some(&name),
                    app: self.app.as_ref(),
                });
                ctx.sink.emit(Event::FlowNamed {
                    id: self.id,
                    name,
                    source: NameSource::Sni,
                });
                self.named = true;
                if verdict == Verdict::Block {
                    self.quic = None;
                    self.finished = Some(CloseReason::Blocked);
                } else {
                    self.release();
                }
            }
            QuicSni::Incomplete if hold.held.len() < MAX_HELD => {}
            _ => self.resolve_unnamed(ctx),
        }
    }

    /// Gives up on naming after the wait, as the forwarder's housekeeping.
    pub fn check_quic_timeout(&mut self, ctx: &QuicCtx<'_>) {
        if self
            .quic
            .as_ref()
            .is_some_and(|h| h.started.elapsed() >= ctx.wait)
        {
            self.resolve_unnamed(ctx);
        }
    }

    /// Naming failed or ran out of time.
    fn resolve_unnamed(&mut self, ctx: &QuicCtx<'_>) {
        if ctx.force_tcp_unnamed && !self.named {
            self.quic = None;
            self.finished = Some(CloseReason::ForcedTcp);
        } else {
            self.release();
        }
    }

    /// Sends everything held, in order, and stops holding.
    fn release(&mut self) {
        if let Some(hold) = self.quic.take() {
            for datagram in hold.held {
                self.send(&datagram);
            }
        }
    }

    /// UDP is lossy, so a full socket buffer drops the datagram.
    fn send(&mut self, payload: &[u8]) {
        match self.socket.send(payload) {
            Ok(n) => self.bytes_up += n as u64,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => self.finished = Some(CloseReason::Reset),
        }
    }

    /// Server to app: every datagram waiting on the socket becomes a packet
    /// in `out`. DNS answers feed the name cache on the way through.
    pub fn receive(
        &mut self,
        scratch: &mut [u8],
        out: &mut Vec<Vec<u8>>,
        names: &mut DnsCache,
        sink: &dyn EventSink,
        now_ms: i64,
    ) {
        loop {
            match self.socket.recv(scratch) {
                Ok(n) => {
                    let payload = &scratch[..n];
                    self.last_active = Instant::now();
                    self.bytes_down += n as u64;
                    if self.is_dns {
                        self.answered = true;
                        if let Ok(msg) = dns::parse(payload)
                            && let Some((name, addrs)) = names.learn(&msg)
                        {
                            sink.emit(Event::DnsAnswer {
                                at_ms: now_ms,
                                name,
                                addrs,
                            });
                        }
                    }
                    out.push(build::udp_packet(self.key.dst, self.key.src, payload));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    // ICMP unreachable surfaces here on a connected socket.
                    self.finished = Some(CloseReason::Reset);
                    break;
                }
            }
        }
    }
}
