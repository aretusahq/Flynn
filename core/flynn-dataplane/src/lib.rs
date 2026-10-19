//! The data plane: parse each packet, track its flow, decide, forward.
//!
//! This crate is linked into the capture extension, which runs under a hard
//! memory ceiling on iOS. Nothing that grows with traffic belongs here: flows
//! are capped and evicted, events go straight to the spool, and history lives
//! in the app (`flynn-store`). The smoltcp forwarder lands in M1.

pub mod host;

use std::sync::Arc;

use flynn_types::Capabilities;

pub use host::{
    AppResolver, Clock, FlowKey, HostError, Notifier, PacketIo, Paths, SocketProtector, Transport,
};

/// Everything the platform supplies to a data plane.
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
}
