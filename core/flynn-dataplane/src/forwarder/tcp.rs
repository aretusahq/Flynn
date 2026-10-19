//! TCP relay: one smoltcp socket facing the app, one OS socket facing the
//! server, bytes copied between their buffers without staging.

use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::time::Instant;

use flynn_proto::tls;
use flynn_rules::Verdict;
use flynn_types::AppId;
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp::{self, State};

use crate::FlowKey;
use crate::events::{CloseReason, Event, EventSink, FlowId};
use crate::names::NameSource;
use crate::policy::{FlowMeta, Policy};

/// A flow whose outbound connect is still in progress. The app's SYN is
/// held back until the server accepts, so a refused connection reaches the
/// app as a reset instead of a handshake that then dies.
pub(crate) struct PendingTcp {
    pub id: FlowId,
    pub syn: Vec<u8>,
    pub stream: mio::net::TcpStream,
    pub started: Instant,
    pub app: Option<AppId>,
}

pub(crate) struct TcpFlow {
    pub id: FlowId,
    pub key: FlowKey,
    pub handle: SocketHandle,
    pub stream: mio::net::TcpStream,
    pub app: Option<AppId>,
    pub created: Instant,
    pub established: bool,
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
}

enum Read_ {
    Data(usize),
    Eof,
    Blocked,
    Failed,
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
            State::Listen | State::SynReceived => {
                // Waiting for the app to finish its handshake.
                if self.created.elapsed() > ctx.listen_timeout {
                    socket.abort();
                    self.finished = Some(CloseReason::Reset);
                }
                return;
            }
            State::Closed | State::TimeWait => {
                self.finished = Some(self.close_reason());
                return;
            }
            _ => self.established = true,
        }

        if self.sniffing && !self.sniff(socket, ctx) {
            return;
        }
        if !self.sniffing
            && let Err(reason) = self.upload(socket)
        {
            socket.abort();
            self.finished = Some(reason);
            return;
        }
        if let Err(reason) = self.download(socket) {
            socket.abort();
            self.finished = Some(reason);
        }
    }

    fn close_reason(&self) -> CloseReason {
        if self.remote_eof && self.local_eof {
            CloseReason::Normal
        } else {
            CloseReason::Reset
        }
    }

    /// Reads the TLS server name from the first client bytes, re-checking the
    /// policy with it. Returns false while the flow must keep waiting or has
    /// been blocked.
    fn sniff(&mut self, socket: &mut tcp::Socket<'_>, ctx: &mut RelayCtx<'_>) -> bool {
        if socket.recv_queue() == 0 {
            // Nothing from the client yet. A server-speaks-first protocol
            // still needs its download path, so stop sniffing once the
            // server talks.
            return true;
        }
        let first = *self.first_data.get_or_insert_with(Instant::now);
        let n = match socket.peek_slice(ctx.scratch) {
            Ok(n) => n,
            Err(_) => {
                self.sniffing = false;
                return true;
            }
        };
        match tls::client_hello_sni(&ctx.scratch[..n]) {
            tls::Sni::Incomplete
                if n < socket.recv_capacity()
                    && n < tls::MAX_CLIENT_HELLO
                    && first.elapsed() < ctx.sni_wait =>
            {
                return false;
            }
            tls::Sni::Found(name) => {
                let name = name.to_ascii_lowercase();
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
                if verdict == Verdict::Block {
                    socket.abort();
                    self.finished = Some(CloseReason::Blocked);
                    return false;
                }
            }
            _ => {}
        }
        self.sniffing = false;
        true
    }

    /// App to server.
    fn upload(&mut self, socket: &mut tcp::Socket<'_>) -> Result<(), CloseReason> {
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
                Ok(Err(_)) => return Err(CloseReason::Reset),
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
    fn download(&mut self, socket: &mut tcp::Socket<'_>) -> Result<(), CloseReason> {
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
                Err(_) => (0, Read_::Failed),
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
                Ok(Read_::Failed) => return Err(CloseReason::Reset),
                Err(_) => break,
            }
        }
        Ok(())
    }
}
