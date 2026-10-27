//! TCP relay: one smoltcp socket facing the app, one OS socket facing the
//! server, bytes copied between their buffers without staging.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::sync::Mutex;
use std::time::Instant;

use flynn_proto::tls;
use flynn_rules::{Decision, NameState};
use flynn_types::AppId;
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp::{self, State};

use crate::FlowKey;
use crate::events::{CloseReason, Event, EventSink, FlowId};
use crate::names::NameSource;
use crate::policy::{FlowMeta, Policy, Standing};

/// A flow whose outbound connect is still in progress. The app's SYN is
/// held back until the server accepts, so a refused connection reaches the
/// app as a reset instead of a handshake that then dies.
pub(crate) struct PendingTcp {
    pub id: FlowId,
    pub syn: Vec<u8>,
    pub stream: mio::net::TcpStream,
    pub started: Instant,
    pub app: Option<AppId>,
    /// What DNS said about the destination when the flow opened.
    pub name: Option<String>,
    pub standing: Standing,
}

pub(crate) struct TcpFlow {
    pub id: FlowId,
    pub key: FlowKey,
    pub handle: SocketHandle,
    pub stream: mio::net::TcpStream,
    pub app: Option<AppId>,
    pub created: Instant,
    /// Passes in which the socket was still listening. The app's SYN is
    /// handed to it as the flow is created, so the first pass can see
    /// Listen; a second means the app reset the handshake.
    pub listen_passes: u8,
    pub established: bool,
    /// When the app's handshake completed: the start of the quiet period
    /// after which no server name is expected.
    pub established_at: Option<Instant>,
    /// The best name known: from DNS at open, replaced by the TLS server
    /// name when that arrives.
    pub name: Option<String>,
    /// What the log last said about this flow, and whether a decision still
    /// waits on the server name (data is held in both directions until it
    /// arrives or is known never to).
    pub standing: Standing,
    /// Still holding the first client bytes to read the TLS server name.
    pub sniffing: bool,
    pub first_data: Option<Instant>,
    /// The server closed its side; a FIN is queued towards the app.
    pub remote_eof: bool,
    /// The app closed its side; the server socket is shut for writing.
    pub local_eof: bool,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub finished: Option<CloseReason>,
}

pub(crate) struct RelayCtx<'a> {
    pub policy: &'a dyn Policy,
    pub sink: &'a dyn EventSink,
    pub scratch: &'a mut [u8],
    pub sni_wait: std::time::Duration,
    pub listen_timeout: std::time::Duration,
    pub aborts: &'a AbortLog,
    pub now_ms: i64,
}

/// Why TCP flows ended other than by a clean close, so a high reset count
/// can be taken apart: the app resetting, the server failing, or the
/// forwarder giving up. Causes are fixed phrases plus an `io::ErrorKind`,
/// so the set stays small.
#[derive(Default)]
pub(crate) struct AbortLog {
    causes: Mutex<BTreeMap<String, u64>>,
}

impl AbortLog {
    pub fn note(&self, cause: &str) {
        if let Ok(mut causes) = self.causes.lock() {
            *causes.entry(cause.to_string()).or_insert(0) += 1;
        }
    }

    /// Cause and count, most frequent first.
    pub fn snapshot(&self) -> Vec<(String, u64)> {
        let mut all: Vec<(String, u64)> = self
            .causes
            .lock()
            .map(|c| c.iter().map(|(k, v)| (k.clone(), *v)).collect())
            .unwrap_or_default();
        all.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
        all
    }
}

enum Read_ {
    Data(usize),
    Eof,
    Blocked,
    Failed(io::ErrorKind),
}

impl TcpFlow {
    /// Moves bytes both ways and notes when the flow is over. A finished
    /// flow keeps its socket until the next interface poll has sent any
    /// final FIN or RST.
    pub fn relay(&mut self, socket: &mut tcp::Socket<'_>, ctx: &mut RelayCtx<'_>) {
        if self.finished.is_some() {
            return;
        }
        match socket.state() {
            // An app that gave up while we were still connecting to the server
            // (its connection attempt was cancelled, which sends nothing) gets
            // our SYN-ACK in reply to nothing, and its kernel answers with a
            // reset. smoltcp then returns the passive socket to Listen. Without
            // this the flow would hold a server connection and its buffers for
            // the full timeout.
            State::Listen => {
                self.listen_passes = self.listen_passes.saturating_add(1);
                if self.listen_passes >= 2 {
                    socket.abort();
                    ctx.aborts
                        .note("app abandoned the connection before its handshake finished");
                    self.finished = Some(CloseReason::Reset);
                }
                return;
            }
            State::SynReceived => {
                // Waiting for the app to finish its handshake.
                if self.created.elapsed() > ctx.listen_timeout {
                    socket.abort();
                    ctx.aborts
                        .note("app never finished its handshake (timed out)");
                    self.finished = Some(CloseReason::Reset);
                }
                return;
            }
            // TimeWait is reached only by a complete four-way close, whichever
            // side closed first. When the server closes first, the app's FIN
            // takes the socket from FinWait2 straight here, before the app's
            // EOF was ever observed, so the EOF flags cannot decide this.
            State::TimeWait => {
                self.finished = Some(CloseReason::Normal);
                return;
            }
            State::Closed => {
                let reason = self.close_reason();
                if reason == CloseReason::Reset {
                    ctx.aborts.note(self.closed_cause());
                }
                self.finished = Some(reason);
                return;
            }
            _ => {
                self.established = true;
                self.established_at.get_or_insert_with(Instant::now);
            }
        }

        if self.sniffing && !self.sniff(socket, ctx) {
            return;
        }
        if !self.sniffing
            && let Err(kind) = self.upload(socket)
        {
            socket.abort();
            ctx.aborts.note(&format!("server write failed: {kind:?}"));
            self.finished = Some(CloseReason::Reset);
            return;
        }
        if let Err(kind) = self.download(socket) {
            socket.abort();
            ctx.aborts.note(&format!("server read failed: {kind:?}"));
            self.finished = Some(CloseReason::Reset);
        }
    }

    /// Who ended a flow whose socket went straight to Closed, which smoltcp
    /// does when the app resets it.
    fn closed_cause(&self) -> &'static str {
        match (self.established, self.remote_eof, self.local_eof) {
            (false, _, _) => "app reset during the handshake",
            (true, false, false) => "app reset an open connection",
            (true, true, false) => "app reset after the server had finished",
            (true, false, true) => "app finished, then reset while the server was open",
            (true, true, true) => "closed after both sides finished",
        }
    }

    fn close_reason(&self) -> CloseReason {
        if self.remote_eof && self.local_eof {
            CloseReason::Normal
        } else {
            CloseReason::Reset
        }
    }

    /// Decides again with what is known about the name now, and tells the
    /// log if the verdict or its reason changed. `Wait` leaves everything as
    /// it was.
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
    /// changed.
    pub fn recheck(&mut self, policy: &dyn Policy, sink: &dyn EventSink, now_ms: i64) -> Decision {
        let name = self.name.clone();
        let state = match &name {
            Some(n) => NameState::Known(n),
            None if self.standing.awaiting_name => NameState::Pending,
            None => NameState::Unavailable,
        };
        self.redecide(state, policy, sink, now_ms)
    }

    /// Reads the TLS server name from the first client bytes and decides
    /// with it. Returns false while the flow must keep waiting or has been
    /// blocked.
    fn sniff(&mut self, socket: &mut tcp::Socket<'_>, ctx: &mut RelayCtx<'_>) -> bool {
        if socket.recv_queue() == 0 {
            if !self.standing.awaiting_name {
                // Nothing from the client yet, and nothing hangs on a name:
                // a server that speaks first needs its download path.
                return true;
            }
            // A decision waits on the name, so nothing moves either way. But
            // not for ever: a protocol where the server speaks first never
            // sends a ClientHello.
            let quiet = self
                .established_at
                .is_some_and(|t| t.elapsed() >= ctx.sni_wait);
            return if quiet {
                self.settle_without_name(socket, ctx)
            } else {
                false
            };
        }
        let first = *self.first_data.get_or_insert_with(Instant::now);
        let n = match socket.peek_slice(ctx.scratch) {
            Ok(n) => n,
            Err(_) => return self.settle_without_name(socket, ctx),
        };
        match tls::client_hello_sni(&ctx.scratch[..n]) {
            tls::Sni::Incomplete
                if n < socket.recv_capacity()
                    && n < tls::MAX_CLIENT_HELLO
                    && first.elapsed() < ctx.sni_wait =>
            {
                false
            }
            tls::Sni::Found(name) => {
                let name = name.to_ascii_lowercase();
                ctx.sink.emit(Event::FlowNamed {
                    id: self.id,
                    name: name.clone(),
                    source: NameSource::Sni,
                });
                self.name = Some(name.clone());
                let decision =
                    self.redecide(NameState::Known(&name), ctx.policy, ctx.sink, ctx.now_ms);
                if matches!(decision, Decision::Block(_)) {
                    socket.abort();
                    self.finished = Some(CloseReason::Blocked);
                    return false;
                }
                self.sniffing = false;
                true
            }
            // Not TLS, no server name in it, or too slow to arrive.
            _ => self.settle_without_name(socket, ctx),
        }
    }

    /// No server name is coming. Decide with what is known (a name from DNS,
    /// or none) and carry on, or block.
    fn settle_without_name(
        &mut self,
        socket: &mut tcp::Socket<'_>,
        ctx: &mut RelayCtx<'_>,
    ) -> bool {
        self.sniffing = false;
        let name = self.name.clone();
        let state = match &name {
            Some(n) => NameState::Known(n),
            None => NameState::Unavailable,
        };
        let decision = self.redecide(state, ctx.policy, ctx.sink, ctx.now_ms);
        if matches!(decision, Decision::Block(_)) {
            socket.abort();
            self.finished = Some(CloseReason::Blocked);
            return false;
        }
        true
    }

    /// App to server.
    fn upload(&mut self, socket: &mut tcp::Socket<'_>) -> Result<(), io::ErrorKind> {
        while socket.can_recv() {
            let stream = &mut self.stream;
            let result = socket.recv(|buf| match stream.write(buf) {
                Ok(n) => (n, Ok(n)),
                Err(e) => (0, Err(e)),
            });
            match result {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => self.bytes_up += n as u64,
                Ok(Err(e)) if e.kind() == io::ErrorKind::WouldBlock => break,
                Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(e)) => return Err(e.kind()),
                Err(_) => break,
            }
        }
        if self.established && !socket.may_recv() && socket.recv_queue() == 0 && !self.local_eof {
            let _ = self.stream.shutdown(Shutdown::Write);
            self.local_eof = true;
        }
        Ok(())
    }

    /// Server to app.
    fn download(&mut self, socket: &mut tcp::Socket<'_>) -> Result<(), io::ErrorKind> {
        while !self.remote_eof && socket.can_send() {
            let stream = &mut self.stream;
            let result = socket.send(|buf| match stream.read(buf) {
                Ok(0) => (0, Read_::Eof),
                Ok(n) => (n, Read_::Data(n)),
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::Interrupted =>
                {
                    (0, Read_::Blocked)
                }
                Err(e) => (0, Read_::Failed(e.kind())),
            });
            match result {
                Ok(Read_::Data(n)) => {
                    self.bytes_down += n as u64;
                    // The server spoke first: this is not a TLS client flow.
                    self.sniffing = false;
                }
                Ok(Read_::Eof) => {
                    self.remote_eof = true;
                    socket.close();
                }
                Ok(Read_::Blocked) => break,
                Ok(Read_::Failed(kind)) => return Err(kind),
                Err(_) => break,
            }
        }
        Ok(())
    }
}
