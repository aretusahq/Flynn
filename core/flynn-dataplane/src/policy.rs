//! What decides a connection's fate, and how the rules reach it.
//!
//! The forwarder asks a [`Policy`] at three moments: when a flow opens, when
//! its server name is learned (or known never to come), and whenever the
//! rules change. [`RulesPolicy`] answers from a compiled
//! [`RuleSet`](flynn_rules::RuleSet) that can be replaced while the tunnel
//! runs: the app rewrites the snapshot file and sends a reload message.

use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use flynn_rules::snapshot::{self, SnapshotError};
use flynn_rules::{
    Action, Config, Decision, Dest, Mode, NameState, Query, Reason, Rule, RuleError, RuleSet,
    Verdict,
};
use flynn_types::AppId;

use crate::FlowKey;

/// What is known about a flow when a decision is made.
#[derive(Debug, Clone, Copy)]
pub struct FlowMeta<'a> {
    pub key: &'a FlowKey,
    pub name: NameState<'a>,
    pub app: Option<&'a AppId>,
}

pub trait Policy: Send + Sync {
    fn decide(&self, flow: &FlowMeta<'_>) -> Decision;

    /// Changes whenever the rules do, so the forwarder knows to look at its
    /// open flows again. A policy that never changes can leave this as is.
    fn generation(&self) -> u64 {
        0
    }
}

/// A decision as the log records it: a verdict and a reason. A flow that is
/// still waiting for its name is provisionally allowed (its data is held),
/// and says so.
pub fn provisional(decision: Decision) -> (Verdict, Reason) {
    match decision {
        Decision::Allow(reason) => (Verdict::Allow, reason),
        Decision::Block(reason) => (Verdict::Block, reason),
        Decision::Wait => (Verdict::Allow, Reason::AwaitingName),
    }
}

/// What the log last said about a flow, and whether a decision still waits
/// on its server name. One place for the bookkeeping every kind of flow
/// needs.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Standing {
    pub verdict: Verdict,
    pub reason: Reason,
    pub awaiting_name: bool,
}

impl Standing {
    pub fn from_decision(decision: Decision) -> Self {
        let (verdict, reason) = provisional(decision);
        Self {
            verdict,
            reason,
            awaiting_name: decision == Decision::Wait,
        }
    }

    /// Takes a new decision. Returns the verdict and reason if they differ
    /// from what the log said, so the caller can log the change. `Wait`
    /// changes nothing.
    pub fn update(&mut self, decision: Decision) -> Option<(Verdict, Reason)> {
        if decision == Decision::Wait {
            return None;
        }
        self.awaiting_name = false;
        let (verdict, reason) = provisional(decision);
        if (verdict, reason) == (self.verdict, self.reason) {
            return None;
        }
        self.verdict = verdict;
        self.reason = reason;
        Some((verdict, reason))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("reading the rules failed: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Snapshot(#[from] SnapshotError),
    #[error(transparent)]
    Rules(#[from] RuleError),
}

/// Reads and compiles the snapshot at `path`. `Ok(None)` means there is no
/// file, which is how a fresh install looks.
pub fn load_rules(path: &Path) -> Result<Option<RuleSet>, LoadError> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    Ok(Some(snapshot::decode(&bytes)?.compile()?))
}

/// The rules, replaceable while the forwarder runs.
pub struct RulesPolicy {
    current: RwLock<Arc<RuleSet>>,
    /// Counts replacements; the forwarder compares it to notice a change,
    /// whatever generation numbers the snapshots carry.
    epoch: AtomicU64,
}

impl RulesPolicy {
    pub fn new(rules: RuleSet) -> Self {
        Self {
            current: RwLock::new(Arc::new(rules)),
            epoch: AtomicU64::new(1),
        }
    }

    pub fn from_config(config: &Config) -> Result<Self, RuleError> {
        Ok(Self::new(RuleSet::compile(config, 0)?))
    }

    pub fn allow_all() -> Self {
        Self::new(RuleSet::allow_all())
    }

    /// No rules, just a mode.
    pub fn mode(mode: Mode) -> Self {
        let config = Config {
            mode,
            ..Config::default()
        };
        Self::from_config(&config).unwrap_or_else(|_| Self::allow_all())
    }

    /// Allow-all, with a block rule for each domain and everything under it.
    /// For tests and the harness's `--block`.
    pub fn blocking_domains<I, S>(domains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut config = Config::default();
        for d in domains {
            let d = d.as_ref();
            for dest in [Dest::Domain(d.to_string()), Dest::Subdomains(d.to_string())] {
                config.rules.push(Rule {
                    id: config.rules.len() as u32 + 1,
                    action: Action::Block,
                    dest,
                    app: None,
                    ports: None,
                    transport: None,
                });
            }
        }
        Self::from_config(&config).unwrap_or_else(|_| Self::allow_all())
    }

    pub fn rules(&self) -> Arc<RuleSet> {
        self.current
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Swaps in new rules. Flows already open are looked at again on the
    /// forwarder's next pass.
    pub fn replace(&self, rules: RuleSet) {
        *self.current.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(rules);
        self.epoch.fetch_add(1, Ordering::AcqRel);
    }
}

impl Policy for RulesPolicy {
    fn decide(&self, flow: &FlowMeta<'_>) -> Decision {
        self.rules().decide(&Query {
            transport: flow.key.protocol,
            dst: flow.key.dst.ip(),
            port: flow.key.dst.port(),
            name: flow.name,
            app: flow.app,
        })
    }

    fn generation(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Transport;

    fn key() -> FlowKey {
        FlowKey {
            protocol: Transport::Tcp,
            src: "10.0.0.2:5000".parse().unwrap(),
            dst: "1.2.3.4:443".parse().unwrap(),
        }
    }

    fn decide(policy: &dyn Policy, name: NameState<'_>) -> Decision {
        policy.decide(&FlowMeta {
            key: &key(),
            name,
            app: None,
        })
    }

    #[test]
    fn blocking_domains_covers_the_domain_and_its_subdomains() {
        let p = RulesPolicy::blocking_domains(["tracker.example"]);
        for blocked in ["tracker.example", "a.b.Tracker.Example"] {
            assert!(matches!(
                decide(&p, NameState::Known(blocked)),
                Decision::Block(_)
            ));
        }
        for allowed in ["nottracker.example", "example"] {
            assert!(matches!(
                decide(&p, NameState::Known(allowed)),
                Decision::Allow(_)
            ));
        }
        assert_eq!(decide(&p, NameState::Pending), Decision::Wait);
    }

    #[test]
    fn replacing_the_rules_changes_decisions_and_the_generation() {
        let p = RulesPolicy::allow_all();
        let before = p.generation();
        assert!(matches!(
            decide(&p, NameState::Unavailable),
            Decision::Allow(_)
        ));
        p.replace(
            RuleSet::compile(
                &Config {
                    mode: Mode::Lockdown,
                    ..Config::default()
                },
                0,
            )
            .unwrap(),
        );
        assert_ne!(p.generation(), before);
        assert_eq!(
            decide(&p, NameState::Unavailable),
            Decision::Block(Reason::Lockdown)
        );
    }

    #[test]
    fn waiting_is_logged_as_a_provisional_allow() {
        assert_eq!(
            provisional(Decision::Wait),
            (Verdict::Allow, Reason::AwaitingName)
        );
        assert_eq!(
            provisional(Decision::Block(Reason::Lockdown)),
            (Verdict::Block, Reason::Lockdown)
        );
    }

    #[test]
    fn a_missing_snapshot_is_not_an_error_but_a_damaged_one_is() {
        let dir = std::env::temp_dir().join(format!("flynn-policy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rules.snapshot");
        assert!(load_rules(&path).unwrap().is_none());

        let bytes = snapshot::encode(
            &Config {
                mode: Mode::BlockAll,
                ..Config::default()
            },
            5,
        )
        .unwrap();
        std::fs::write(&path, &bytes).unwrap();
        let rules = load_rules(&path).unwrap().unwrap();
        assert_eq!((rules.mode(), rules.generation()), (Mode::BlockAll, 5));

        let mut bad = bytes;
        let last = bad.len() - 1;
        bad[last] ^= 0xff;
        std::fs::write(&path, &bad).unwrap();
        assert!(matches!(load_rules(&path), Err(LoadError::Snapshot(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
