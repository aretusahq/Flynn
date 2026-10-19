//! What the data plane reports. Events go to a sink: the spool on devices
//! (see `spool`), printed lines in the harness.

use std::net::IpAddr;

use flynn_rules::Verdict;
use flynn_types::AppId;

use crate::mem::MemSample;
use crate::{FlowKey, NameSource, StatsSnapshot};

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
    /// Periodic measurement of the capture process and forwarder counters.
    Sample {
        at_ms: i64,
        mem: MemSample,
        stats: StatsSnapshot,
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

    /// Called on every forwarder pass, so a buffering sink can flush on a
    /// timer without a thread of its own.
    fn tick(&self) {}
}

/// Discards every event.
pub struct NullSink;

impl EventSink for NullSink {
    fn emit(&self, _event: Event) {}
}
