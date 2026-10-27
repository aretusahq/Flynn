//! UniFFI bindings for every host.
//!
//! One crate, two facades: [`FlynnDataPlane`] for capture extensions, and
//! free functions for the app (the spool reader now, the Library store from
//! M5). Swift and Kotlin are both generated from this crate; hosts implement
//! the `Host*` traits to supply platform behaviour.

mod dataplane;
mod library;
mod rules;
mod selftest;

pub use dataplane::*;
pub use library::*;
pub use rules::*;
pub use selftest::*;

use flynn_dataplane::{CloseReason, MemSample, NameSource, StatsSnapshot, Transport};
use flynn_rules::{Action, Mode, Reason, Verdict};
use flynn_types::{AppId, Capabilities, LeakScope, Platform};

uniffi::setup_scaffolding!();

/// Version of the Rust core, shown in the app's about screen and logs.
#[uniffi::export]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FlynnError {
    #[error("{message}")]
    Io { message: String },
    #[error("invalid settings: {message}")]
    InvalidSettings { message: String },
    #[error("the data plane is already running")]
    AlreadyRunning,
    #[error("invalid rules: {message}")]
    InvalidRules { message: String },
}

impl From<std::io::Error> for FlynnError {
    fn from(e: std::io::Error) -> Self {
        FlynnError::Io {
            message: e.to_string(),
        }
    }
}

// Shared types, re-declared for UniFFI from the core crates.

#[uniffi::remote(Enum)]
pub enum Platform {
    Ios,
    Android,
    Macos,
    Windows,
    Linux,
}

#[uniffi::remote(Enum)]
pub enum LeakScope {
    None,
    Device,
    PerApp,
}

#[uniffi::remote(Record)]
pub struct AppId {
    pub platform: Platform,
    pub id: String,
    pub display_name: Option<String>,
}

#[uniffi::remote(Record)]
pub struct Capabilities {
    pub per_app_available: bool,
    pub can_pause_flow: bool,
    pub leak_detection_scope: LeakScope,
}

#[uniffi::remote(Enum)]
pub enum Transport {
    Tcp,
    Udp,
}

#[uniffi::remote(Enum)]
pub enum Mode {
    AllowAll,
    BlockAll,
    Lockdown,
}

#[uniffi::remote(Enum)]
pub enum Verdict {
    Allow,
    Block,
}

#[uniffi::remote(Enum)]
pub enum Action {
    Allow,
    Block,
}

/// Why a connection got its verdict.
#[uniffi::remote(Enum)]
pub enum Reason {
    Panic,
    Lockdown,
    Rule { id: u32 },
    Essential,
    ModeDefault,
    AwaitingName,
}

#[uniffi::remote(Enum)]
pub enum NameSource {
    None,
    Dns,
    Sni,
}

#[uniffi::remote(Enum)]
pub enum CloseReason {
    Normal,
    Reset,
    Blocked,
    ConnectFailed,
    Idle,
    Capacity,
    ForcedTcp,
    Shutdown,
}

#[uniffi::remote(Record)]
pub struct MemSample {
    pub footprint: u64,
    pub peak_footprint: u64,
    pub cpu_ms: u64,
}

#[uniffi::remote(Record)]
pub struct StatsSnapshot {
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub tcp_active: u64,
    pub udp_active: u64,
    pub flows_opened: u64,
    pub flows_blocked: u64,
    pub connect_failed: u64,
    pub dropped: u64,
}
