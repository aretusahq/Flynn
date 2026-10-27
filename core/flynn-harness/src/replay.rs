//! `replay`: run a capture through the parsers, naming and policy, and
//! print one line per flow.

use std::fmt::Write as _;
use std::sync::Arc;

use flynn_dataplane::observe::{FlowSummary, FlowTracker};
use flynn_dataplane::{Policy, Transport};
use flynn_rules::{Reason, Verdict};

use crate::pcap::Capture;

pub fn report(capture: &Capture, policy: Arc<dyn Policy>) -> String {
    let mut tracker = FlowTracker::new(policy);
    for p in &capture.packets {
        tracker.observe(p.at_ms, &p.ip);
    }
    let skipped = tracker.skipped + capture.unsupported;
    let flows = tracker.finish();

    let mut out = String::new();
    let _ = writeln!(out, "flows: {}  skipped packets: {skipped}", flows.len());
    for (i, f) in flows.iter().enumerate() {
        let _ = writeln!(out, "#{} {}", i + 1, line(f));
    }
    out
}

/// A reason as it reads in logs: `rule#3`, `default`, `essential`...
pub fn why(reason: Reason) -> String {
    match reason {
        Reason::Panic => "panic".into(),
        Reason::Lockdown => "lockdown".into(),
        Reason::Rule { id } => format!("rule#{id}"),
        Reason::Essential => "essential".into(),
        Reason::ModeDefault => "default".into(),
        Reason::AwaitingName => "awaiting-name".into(),
    }
}

fn line(f: &FlowSummary) -> String {
    let proto = match f.key.protocol {
        Transport::Tcp => "tcp",
        Transport::Udp => "udp",
    };
    let name = match &f.name {
        Some(n) => format!("{n} ({})", f.source.as_str()),
        None => "-".to_string(),
    };
    let verdict = match f.verdict {
        Verdict::Allow => "allow",
        Verdict::Block => "block",
    };
    format!(
        "{proto} {} -> {} name={name} verdict={verdict} why={}{} up={}p/{}B down={}p/{}B",
        f.key.src,
        f.key.dst,
        why(f.reason),
        if f.quic { " quic" } else { "" },
        f.packets_up,
        f.bytes_up,
        f.packets_down,
        f.bytes_down,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fixture, pcap};
    use flynn_dataplane::RulesPolicy;

    const PCAP: &[u8] = include_bytes!("../../fixtures/synthetic-basic.pcap");

    /// Each case replays the same capture under a rules file and must give
    /// the checked-in output: name, rules, expected.
    const CASES: &[(&str, &str, &str)] = &[
        (
            "basic",
            include_str!("../../fixtures/synthetic-basic.rules"),
            include_str!("../../fixtures/synthetic-basic.expected.txt"),
        ),
        (
            "blockall",
            include_str!("../../fixtures/synthetic-blockall.rules"),
            include_str!("../../fixtures/synthetic-blockall.expected.txt"),
        ),
        (
            "lockdown",
            include_str!("../../fixtures/synthetic-lockdown.rules"),
            include_str!("../../fixtures/synthetic-lockdown.expected.txt"),
        ),
        (
            "panic",
            include_str!("../../fixtures/synthetic-panic.rules"),
            include_str!("../../fixtures/synthetic-panic.expected.txt"),
        ),
        (
            "precedence",
            include_str!("../../fixtures/synthetic-precedence.rules"),
            include_str!("../../fixtures/synthetic-precedence.expected.txt"),
        ),
    ];

    #[test]
    fn committed_fixture_matches_generator() {
        let mut fresh = Vec::new();
        pcap::write_raw(&mut fresh, &fixture::basic()).unwrap();
        assert!(
            fresh == PCAP,
            "fixtures/synthetic-basic.pcap is stale; run `flynn-harness gen-fixture`"
        );
    }

    #[test]
    fn replay_matches_expected_for_every_rule_case() {
        let capture = pcap::read(PCAP).unwrap();
        for (name, rules, expected) in CASES {
            let config = flynn_rules::text::parse(rules).unwrap();
            let policy = Arc::new(RulesPolicy::from_config(&config).unwrap());
            assert_eq!(report(&capture, policy), *expected, "case {name}");
        }
    }
}
