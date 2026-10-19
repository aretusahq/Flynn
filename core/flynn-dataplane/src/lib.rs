//! The data plane: parse each packet, track its flow, decide, forward.
//!
//! This crate is linked into the capture extension, which runs under a hard
//! memory ceiling on iOS. Nothing that grows with traffic belongs here: flow
//! tables and the name cache are capped, events leave through a sink, and
//! history lives in the app (`flynn-store`).

pub mod events;
pub mod forwarder;
pub mod host;
pub mod mem;
pub mod names;
pub mod observe;
pub mod policy;
pub mod spool;

use std::sync::Arc;

use flynn_types::Capabilities;

pub use events::{CloseReason, Event, EventSink, FlowId, NullSink};
pub use forwarder::{ForwarderConfig, ForwarderHandle, StatsSnapshot};
pub use host::{
    AppResolver, Clock, FlowKey, HostError, Notifier, PacketIo, Paths, SocketProtector, Transport,
};
pub use mem::MemSample;
pub use names::NameSource;
pub use policy::{DomainBlocklist, FlowMeta, ModePolicy, Policy};

/// Everything the platform supplies to a data plane.
#[derive(Clone)]
pub struct Host {
    pub packets: Arc<dyn PacketIo>,
    pub protector: Arc<dyn SocketProtector>,
    pub apps: Arc<dyn AppResolver>,
    pub clock: Arc<dyn Clock>,
    pub paths: Arc<dyn Paths>,
    pub notifier: Arc<dyn Notifier>,
}

pub struct DataPlane {
    host: Host,
    capabilities: Capabilities,
}

impl DataPlane {
    pub fn new(host: Host, capabilities: Capabilities) -> Self {
        Self { host, capabilities }
    }

    pub fn capabilities(&self) -> Capabilities {
        self.capabilities
    }

    /// Called when the host's level changes, for example when a content
    /// filter becomes available on a supervised device.
    pub fn set_capabilities(&mut self, capabilities: Capabilities) {
        self.capabilities = capabilities;
    }

    pub fn host(&self) -> &Host {
        &self.host
    }

    /// Starts the forwarder on its own thread.
    pub fn start(
        &self,
        config: ForwarderConfig,
        sink: Arc<dyn EventSink>,
    ) -> std::io::Result<ForwarderHandle> {
        forwarder::spawn(self.host.clone(), config, sink)
    }
}
