//! Rules, how they are ranked, and the snapshot file that carries them.
//!
//! The app builds a [`Config`], writes it as a snapshot (see [`snapshot`]);
//! the capture extension reads the snapshot, compiles it into a [`RuleSet`]
//! and swaps it in on a reload message, without restarting the tunnel. The
//! snapshot format and every decision are the same on every platform. See
//! docs/rules.md for the semantics.

mod essentials;
mod model;
mod ruleset;
pub mod snapshot;
pub mod text;

pub use essentials::{EXACT as ESSENTIAL_EXACT, SUBDOMAINS as ESSENTIAL_SUBDOMAINS};
pub use flynn_types::{AppId, Transport};
pub use model::{
    Action, Config, Dest, MAX_RULES, Mode, PortRange, Rule, RuleError, Verdict, normalize_domain,
};
pub use ruleset::{Decision, NameState, Query, Reason, RuleSet};

/// Bumped whenever the snapshot layout changes. A data plane refuses a
/// snapshot with another version rather than misreading it.
pub const SNAPSHOT_FORMAT_VERSION: u16 = 1;
