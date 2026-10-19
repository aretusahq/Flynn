//! UDP relay: one connected OS socket per flow, replies rebuilt as IP
//! packets addressed back to the app.

use std::io;
use std::time::Instant;

use flynn_proto::{build, dns};

use crate::FlowKey;
use crate::events::{CloseReason, Event, EventSink, FlowId};
use crate::names::DnsCache;

pub(crate) struct UdpFlow {
    pub id: FlowId,
    pub key: FlowKey,
    pub socket: mio::net::UdpSocket,
    pub last_active: Instant,
    pub is_dns: bool,
    pub answered: bool,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub finished: Option<CloseReason>,
}

impl UdpFlow {
    /// App to server. UDP is lossy, so a full socket buffer drops the datagram.
    pub fn send(&mut self, payload: &[u8]) {
        self.last_active = Instant::now();
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
