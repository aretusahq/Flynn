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
use flynn_rules::{Decision, NameState};
use flynn_types::AppId;

use crate::FlowKey;
use crate::events::{CloseReason, Event, EventSink, FlowId};
use crate::names::{DnsCache, NameSource};
use crate::policy::{FlowMeta, Policy, Standing};

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
    /// The best name known: from DNS at open, replaced by the name read from
    /// the QUIC Initial packets.
    pub name: Option<String>,
    /// What the log last said about this flow, and whether a decision still
    /// waits on the server name.
    pub standing: Standing,
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
    pub now_ms: i64,
}

impl UdpFlow {
    /// Decides again with what is known about the name now, and tells the
    /// log if the verdict or its reason changed. `Wait` changes nothing.
    pub fn redecide(
        &mut self,
        name: NameState<'_>,
        policy: &dyn Policy,
        sink: &dyn EventSink,
        now_ms: i64,
    ) -> Decision {
        let decision = policy.decide(&FlowMeta {
            key: &self.key,
            name,
            app: self.app.as_ref(),
        });
        if let Some((verdict, reason)) = self.standing.update(decision) {
            sink.emit(Event::FlowDecided {
                id: self.id,
                at_ms: now_ms,
                verdict,
                reason,
            });
        }
        decision
    }

    /// Decides again from the name this flow already has, after the rules
    /// changed. A flow still holding its first datagrams may yet be named.
    pub fn recheck(&mut self, policy: &dyn Policy, sink: &dyn EventSink, now_ms: i64) -> Decision {
        let name = self.name.clone();
        let state = match &name {
            Some(n) => NameState::Known(n),
            None if self.quic.is_some() => NameState::Pending,
            None => NameState::Unavailable,
        };
        self.redecide(state, policy, sink, now_ms)
    }

    /// App to server. Held while a QUIC flow is being named; otherwise sent.
    pub fn handle_app_datagram(&mut self, payload: &[u8], ctx: &QuicCtx<'_>) {
        self.last_active = Instant::now();
        let Some(hold) = self.quic.as_mut() else {
            self.send(payload);
            return;
        };
        hold.held.push(payload.to_vec());
        let held = hold.held.len();
        match hold.sniffer.feed(payload) {
            QuicSni::Found(name) => {
                ctx.sink.emit(Event::FlowNamed {
                    id: self.id,
                    name: name.clone(),
                    source: NameSource::Sni,
                });
                self.name = Some(name.clone());
                let decision =
                    self.redecide(NameState::Known(&name), ctx.policy, ctx.sink, ctx.now_ms);
                if matches!(decision, Decision::Block(_)) {
                    self.quic = None;
                    self.finished = Some(CloseReason::Blocked);
                } else {
                    self.release();
                }
            }
            QuicSni::Incomplete if held < MAX_HELD => {}
            _ => self.settle_without_name(ctx),
        }
    }

    /// Gives up on naming after the wait, as the forwarder's housekeeping.
    pub fn check_quic_timeout(&mut self, ctx: &QuicCtx<'_>) {
        if self
            .quic
            .as_ref()
            .is_some_and(|h| h.started.elapsed() >= ctx.wait)
        {
            self.settle_without_name(ctx);
        }
    }

    /// Naming failed or ran out of time. Decide with what is known; a block
    /// stands, and an unnamed flow may be dropped to push the app to TCP.
    fn settle_without_name(&mut self, ctx: &QuicCtx<'_>) {
        let name = self.name.clone();
        let state = match &name {
            Some(n) => NameState::Known(n),
            None => NameState::Unavailable,
        };
        let decision = self.redecide(state, ctx.policy, ctx.sink, ctx.now_ms);
        if matches!(decision, Decision::Block(_)) {
            self.quic = None;
            self.finished = Some(CloseReason::Blocked);
        } else if ctx.force_tcp_unnamed && self.name.is_none() {
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
