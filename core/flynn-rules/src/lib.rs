//! Rule model, matchers and modes.
//!
//! The app compiles rules into an immutable snapshot file; the capture
//! extension loads it and swaps it in on a reload message without restarting
//! the tunnel. The snapshot format is the same on every platform. Matchers
//! for app, domain, IP/CIDR and port land in M4.

pub use flynn_types::AppId;

/// Bumped whenever the compiled snapshot layout changes. A data plane refuses
/// a snapshot with a different version rather than misreading it.
pub const SNAPSHOT_FORMAT_VERSION: u16 = 1;

/// What happens to a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Block,
}

/// The default applied to connections no rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Allow anything not explicitly blocked.
    AllowAll,
    /// Block anything not explicitly allowed, except the essentials list.
    BlockAll,
    /// Block everything, essentials included. Every attempt is still logged.
    Lockdown,
}

impl Mode {
    /// The verdict for an unmatched connection. `essential` says whether the
    /// destination is on the essentials allow-list; `panic` is the one-tap
    /// override that restores all traffic.
    pub fn default_verdict(self, essential: bool, panic: bool) -> Verdict {
        if panic {
            return Verdict::Allow;
        }
        match self {
            Mode::AllowAll => Verdict::Allow,
            Mode::BlockAll if essential => Verdict::Allow,
            Mode::BlockAll | Mode::Lockdown => Verdict::Block,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_all_keeps_essentials_lockdown_does_not() {
        assert_eq!(Mode::BlockAll.default_verdict(true, false), Verdict::Allow);
        assert_eq!(Mode::BlockAll.default_verdict(false, false), Verdict::Block);
        assert_eq!(Mode::Lockdown.default_verdict(true, false), Verdict::Block);
    }

    #[test]
    fn panic_overrides_every_mode() {
        for mode in [Mode::AllowAll, Mode::BlockAll, Mode::Lockdown] {
            assert_eq!(mode.default_verdict(false, true), Verdict::Allow);
        }
    }
}
