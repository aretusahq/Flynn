//! The decision hook. M1 ships the mode default and a test blocklist; the
//! compiled rule snapshot from `flynn-rules` replaces them in M4.

use flynn_rules::{Mode, Verdict};
use flynn_types::AppId;

use crate::FlowKey;

/// What is known about a flow when a decision is made.
#[derive(Debug, Clone, Copy)]
pub struct FlowMeta<'a> {
    pub key: &'a FlowKey,
    pub name: Option<&'a str>,
    pub app: Option<&'a AppId>,
}

pub trait Policy: Send + Sync {
    fn decide(&self, flow: &FlowMeta<'_>) -> Verdict;
}

/// Applies the mode default to every flow.
pub struct ModePolicy(pub Mode);

impl Policy for ModePolicy {
    fn decide(&self, _flow: &FlowMeta<'_>) -> Verdict {
        self.0.default_verdict(false, false)
    }
}

/// Blocks flows whose name equals or is a subdomain of a listed domain;
/// allows everything else. For the harness and tests until M4's rules.
pub struct DomainBlocklist {
    domains: Vec<String>,
}

impl DomainBlocklist {
    pub fn new(domains: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            domains: domains
                .into_iter()
                .map(|d| d.into().trim_matches('.').to_ascii_lowercase())
                .collect(),
        }
    }

    fn matches(&self, name: &str) -> bool {
        let name = name.trim_end_matches('.');
        self.domains.iter().any(|d| {
            name.eq_ignore_ascii_case(d)
                || (name.len() > d.len()
                    && name.as_bytes()[name.len() - d.len() - 1] == b'.'
                    && name[name.len() - d.len()..].eq_ignore_ascii_case(d))
        })
    }
}

impl Policy for DomainBlocklist {
    fn decide(&self, flow: &FlowMeta<'_>) -> Verdict {
        match flow.name {
            Some(name) if self.matches(name) => Verdict::Block,
            _ => Verdict::Allow,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Transport;

    fn decide(policy: &dyn Policy, name: Option<&str>) -> Verdict {
        let key = FlowKey {
            protocol: Transport::Tcp,
            src: "10.0.0.2:5000".parse().unwrap(),
            dst: "1.2.3.4:443".parse().unwrap(),
        };
        policy.decide(&FlowMeta {
            key: &key,
            name,
            app: None,
        })
    }

    #[test]
    fn blocklist_matches_domain_and_subdomains_only() {
        let p = DomainBlocklist::new(["tracker.example"]);
        assert_eq!(decide(&p, Some("tracker.example")), Verdict::Block);
        assert_eq!(decide(&p, Some("a.b.Tracker.Example")), Verdict::Block);
        assert_eq!(decide(&p, Some("nottracker.example")), Verdict::Allow);
        assert_eq!(decide(&p, None), Verdict::Allow);
    }

    #[test]
    fn mode_policy_uses_mode_default() {
        assert_eq!(decide(&ModePolicy(Mode::AllowAll), None), Verdict::Allow);
        assert_eq!(
            decide(&ModePolicy(Mode::Lockdown), Some("x")),
            Verdict::Block
        );
    }
}
