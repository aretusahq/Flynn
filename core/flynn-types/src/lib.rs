//! Platform-neutral types shared by every Flynn crate and every host.
//!
//! Nothing here may name an Apple or Android API. Hosts translate their own
//! identifiers into these types at the boundary, so rules, the store and
//! exports read the same on every platform.

/// The operating system a host runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Platform {
    Ios,
    Android,
    Macos,
    Windows,
    Linux,
}

/// An app's identity, as reported by the host.
///
/// `id` is a bundle identifier on Apple platforms, a package name on Android,
/// and an executable path on desktop. Rules and the store key on
/// `(platform, id)`; `display_name` is presentation only.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AppId {
    pub platform: Platform,
    pub id: String,
    pub display_name: Option<String>,
}

impl AppId {
    pub fn new(platform: Platform, id: impl Into<String>) -> Self {
        Self {
            platform,
            id: id.into(),
            display_name: None,
        }
    }
}

/// How far the current host can see and act. Filled by the host at startup
/// and whenever its level changes. The UI reads these flags instead of
/// branching on platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// Flows carry an [`AppId`]. False on an unsupervised iPhone or iPad.
    pub per_app_available: bool,
    /// A new flow can be held while the user decides (ask mode).
    pub can_pause_flow: bool,
    /// What leak detection can attribute traffic that bypassed the tunnel to.
    pub leak_detection_scope: LeakScope,
}

impl Capabilities {
    /// The most limited level: an unsupervised iOS device on the packet tunnel.
    pub const TUNNEL_ONLY: Self = Self {
        per_app_available: false,
        can_pause_flow: false,
        leak_detection_scope: LeakScope::Device,
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeakScope {
    /// Leak detection is unavailable on this host.
    None,
    /// Interface counters for the whole device only.
    Device,
    /// Per-app counters (Android usage access).
    PerApp,
}

/// Why Flynn could not see or stop something. Every gap-log entry and every
/// disabled control carries one of these, so a blind spot names itself.
///
/// The UI maps each code to localised text; the core never stores prose.
/// Hosts add their own reasons here rather than inventing strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GapReason {
    /// App names are unavailable because the iOS device is not supervised.
    NotSupervised,
    /// The OS never routes this traffic through any VPN or filter.
    OsExempt(OsExemptKind),
    /// The traffic is not IP (Bluetooth, NFC, Wi-Fi Direct).
    NotIp,
    /// The tunnel was down for this period.
    TunnelDown,
    /// Android: per-app leak counters need the usage-access permission.
    NoUsageAccess,
    /// Android: another VPN app holds the only VPN slot.
    OtherVpnActive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OsExemptKind {
    Dhcp,
    CaptivePortal,
    VoLte,
    CallOrSms,
    CompanionDevice,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_id_keys_on_platform_and_id() {
        let ios = AppId::new(Platform::Ios, "com.example.app");
        let android = AppId::new(Platform::Android, "com.example.app");
        assert_ne!(ios, android);
    }

    // Checked at compile time: the most limited level must never claim
    // per-app visibility or paused flows.
    const _: () = assert!(!Capabilities::TUNNEL_ONLY.per_app_available);
    const _: () = assert!(!Capabilities::TUNNEL_ONLY.can_pause_flow);
}
