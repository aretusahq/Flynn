//! What the data plane reports. In M1 events go to a sink the host
//! supplies (the harness prints them); M2 adds the spool writer.

use std::net::IpAddr;

use flynn_rules::Verdict;
use flynn_types::AppId;

use crate::{FlowKey, NameSource};

pub type FlowId = u64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    FlowOpened {
        id: FlowId,
        at_ms: i64,
        key: FlowKey,
        name: Option<String>,
        source: NameSource,
        app: Option<AppId>,
        verdict: Verdict,
    },
    /// A better name arrived after the flow opened (the TLS server name).
    FlowNamed {
        id: FlowId,
        name: String,
        source: NameSource,
    },
    FlowClosed {
        id: FlowId,
        at_ms: i64,
        bytes_up: u64,
        bytes_down: u64,
        reason: CloseReason,
    },
    DnsAnswer {
        at_ms: i64,
        name: String,
        addrs: Vec<IpAddr>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    /// Both sides finished normally.
    Normal,
    /// Either side reset the connection.
    Reset,
    /// The policy blocked it, at open or when its server name arrived.
    Blocked,
    /// The outbound connection could not be made.
    ConnectFailed,
    /// No traffic for the idle timeout (UDP).
    Idle,
    /// The flow table was full.
    Capacity,
    /// The data plane stopped.
    Shutdown,
}

impl CloseReason {
    pub fn as_str(self) -> &'static str {
        match self {
            CloseReason::Normal => "normal",
            CloseReason::Reset => "reset",
            CloseReason::Blocked => "blocked",
            CloseReason::ConnectFailed => "connect-failed",
            CloseReason::Idle => "idle",
            CloseReason::Capacity => "capacity",
            CloseReason::Shutdown => "shutdown",
        }
    }
}

pub trait EventSink: Send + Sync {
    fn emit(&self, event: Event);
}

/// Discards every event.
pub struct NullSink;

impl EventSink for NullSink {
    fn emit(&self, _event: Event) {}
}
