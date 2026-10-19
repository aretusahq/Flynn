//! `replay`: run a capture through the parsers, naming and policy, and
//! print one line per flow.

use std::fmt::Write as _;
use std::sync::Arc;

use flynn_dataplane::observe::{FlowSummary, FlowTracker};
use flynn_dataplane::{Policy, Transport};
use flynn_rules::Verdict;

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
        "{proto} {} -> {} name={name} verdict={verdict}{} up={}p/{}B down={}p/{}B",
        f.key.src,
        f.key.dst,
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
    use flynn_dataplane::DomainBlocklist;

    const PCAP: &[u8] = include_bytes!("../../fixtures/synthetic-basic.pcap");
    const EXPECTED: &str = include_str!("../../fixtures/synthetic-basic.expected.txt");

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
    fn replay_matches_expected() {
        let capture = pcap::read(PCAP).unwrap();
        let got = report(&capture, Arc::new(DomainBlocklist::new(["tracker.test"])));
        assert_eq!(got, EXPECTED);
    }
}
