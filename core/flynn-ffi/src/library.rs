//! The app facade. M2: reading the spool for the debug screen. The store
//! and explorer queries join it in M5.

use std::path::Path;

use flynn_dataplane::spool;
use flynn_dataplane::{CloseReason, Event, MemSample, NameSource, StatsSnapshot, Transport};
use flynn_rules::Verdict;
use flynn_types::AppId;

use crate::FlynnError;

/// One spool record, flattened for Swift and Kotlin.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum SpoolEvent {
    FlowOpened {
        id: u64,
        at_ms: i64,
        transport: Transport,
        src: String,
        dst: String,
        name: Option<String>,
        source: NameSource,
        app: Option<AppId>,
        verdict: Verdict,
    },
    FlowNamed {
        id: u64,
        name: String,
        source: NameSource,
    },
    FlowClosed {
        id: u64,
        at_ms: i64,
        bytes_up: u64,
        bytes_down: u64,
        reason: CloseReason,
    },
    DnsAnswer {
        at_ms: i64,
        name: String,
        addrs: Vec<String>,
    },
    Sample {
        at_ms: i64,
        mem: MemSample,
        stats: StatsSnapshot,
    },
}

impl From<Event> for SpoolEvent {
    fn from(e: Event) -> Self {
        match e {
            Event::FlowOpened {
                id,
                at_ms,
                key,
                name,
                source,
                app,
                verdict,
            } => SpoolEvent::FlowOpened {
                id,
                at_ms,
                transport: key.protocol,
                src: key.src.to_string(),
                dst: key.dst.to_string(),
                name,
                source,
                app,
                verdict,
            },
            Event::FlowNamed { id, name, source } => SpoolEvent::FlowNamed { id, name, source },
            Event::FlowClosed {
                id,
                at_ms,
                bytes_up,
                bytes_down,
                reason,
            } => SpoolEvent::FlowClosed {
                id,
                at_ms,
                bytes_up,
                bytes_down,
                reason,
            },
            Event::DnsAnswer { at_ms, name, addrs } => SpoolEvent::DnsAnswer {
                at_ms,
                name,
                addrs: addrs.iter().map(ToString::to_string).collect(),
            },
            Event::Sample { at_ms, mem, stats } => SpoolEvent::Sample { at_ms, mem, stats },
        }
    }
}

/// The newest `max` events in the spool directory, oldest first.
#[uniffi::export]
pub fn spool_tail(dir: String, max: u32) -> Result<Vec<SpoolEvent>, FlynnError> {
    Ok(spool::tail(Path::new(&dir), max as usize)?
        .into_iter()
        .map(SpoolEvent::from)
        .collect())
}

/// This process's memory and CPU, for comparing the app with the extension.
#[uniffi::export]
pub fn process_memory() -> MemSample {
    flynn_dataplane::mem::sample()
}
