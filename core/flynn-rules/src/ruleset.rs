//! The compiled rule set and how it decides.
//!
//! Precedence, in the order it is applied:
//!
//! 1. **Panic** allows everything, lockdown included.
//! 2. **Lockdown** blocks everything, allow rules and essentials included.
//! 3. **Rules.** Of all the rules that match, the most specific wins. A rule
//!    is compared on: being for one app; then what it names (an exact domain
//!    or one address, over a wildcard domain, over an address range, over
//!    anything; deeper wildcards and longer prefixes win within a class);
//!    then having a port; then having a transport. Equal specificity: block
//!    beats allow; still equal: the lower id.
//! 4. **The mode's default** for a connection no rule matched. Allow-all
//!    allows. Block-all blocks, except the essentials (unless switched off).
//!
//! A connection's server name often arrives after it opens (the TLS
//! ClientHello, or a QUIC Initial). [`NameState::Pending`] asks the set
//! whether the name could still change the answer; if it could, the answer
//! is [`Decision::Wait`] and nothing is decided yet. The check is
//! conservative: it may wait when a more specific rule of the other action
//! makes the name irrelevant, but it never gives a final answer that a
//! later name could overturn.

use std::borrow::Cow;
use std::cmp::Reverse;
use std::net::IpAddr;

use flynn_types::{AppId, Transport};

use crate::essentials;
use crate::model::{Action, Config, Dest, Mode, PortRange, Rule, RuleError, Verdict};
use crate::model::{addr_bits, mask32, mask128};

/// Why a connection got its verdict. Shown in the explorer, so a block can
/// always say what blocked it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The panic switch is on.
    Panic,
    /// Lockdown mode.
    Lockdown,
    /// This rule (by its id) was the most specific match.
    Rule { id: u32 },
    /// Block-all mode, but the destination is on the essentials list.
    Essential,
    /// No rule matched; the mode's default applied.
    ModeDefault,
    /// Not decided yet: waiting for the server name. Only ever reported by
    /// the data plane for a connection that is still waiting, never by
    /// [`RuleSet::decide`].
    AwaitingName,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow(Reason),
    Block(Reason),
    /// The server name could still change the answer. Hold the connection's
    /// data until the name is known, or until it is certain none will come.
    Wait,
}

impl Decision {
    pub fn verdict(self) -> Option<Verdict> {
        match self {
            Decision::Allow(_) => Some(Verdict::Allow),
            Decision::Block(_) => Some(Verdict::Block),
            Decision::Wait => None,
        }
    }

    pub fn reason(self) -> Option<Reason> {
        match self {
            Decision::Allow(r) | Decision::Block(r) => Some(r),
            Decision::Wait => None,
        }
    }
}

/// What is known about a connection's server name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameState<'a> {
    Known(&'a str),
    /// Not known yet, and one may still arrive.
    Pending,
    /// Not known, and none will arrive (a UDP flow that is not QUIC, a
    /// connection that did not start with TLS, or the wait ran out).
    Unavailable,
}

#[derive(Debug, Clone, Copy)]
pub struct Query<'a> {
    pub transport: Transport,
    pub dst: IpAddr,
    pub port: u16,
    pub name: NameState<'a>,
    /// The app that made the connection, where the platform says.
    pub app: Option<&'a AppId>,
}

struct Compiled {
    id: u32,
    action: Action,
    spec: u32,
    /// 0 for any app, else 1 + an index into `apps`.
    app: u32,
    transport: Option<Transport>,
    ports: Option<PortRange>,
}

struct Net {
    rule: u32,
    addr: IpAddr,
    prefix: u8,
}

/// Domain keys, sorted, in one buffer: no allocation per rule.
#[derive(Default)]
struct DomainIndex {
    blob: String,
    entries: Vec<IndexEntry>,
}

struct IndexEntry {
    off: u32,
    len: u16,
    rule: u32,
}

impl DomainIndex {
    fn build(mut items: Vec<(String, u32)>) -> Self {
        items.sort();
        let mut blob = String::with_capacity(items.iter().map(|(k, _)| k.len()).sum());
        let mut entries = Vec::with_capacity(items.len());
        for (key, rule) in items {
            entries.push(IndexEntry {
                off: blob.len() as u32,
                len: key.len() as u16,
                rule,
            });
            blob.push_str(&key);
        }
        Self { blob, entries }
    }

    fn key(&self, e: &IndexEntry) -> &str {
        &self.blob[e.off as usize..e.off as usize + e.len as usize]
    }

    /// Every rule filed under exactly this key.
    fn lookup<'a>(&'a self, key: &'a str) -> impl Iterator<Item = u32> + 'a {
        let start = self.entries.partition_point(|e| self.key(e) < key);
        self.entries[start..]
            .iter()
            .take_while(move |e| self.key(e) == key)
            .map(|e| e.rule)
    }
}

/// An immutable, compiled set of rules. Cheap to share; replaced whole on a
/// reload.
pub struct RuleSet {
    mode: Mode,
    panic: bool,
    essentials: bool,
    generation: u64,
    rules: Vec<Compiled>,
    apps: Vec<String>,
    exact: DomainIndex,
    subs: DomainIndex,
    any: Vec<u32>,
    nets: Vec<Net>,
    /// Every rule that names a domain, for the "could a name matter" check.
    domain_rules: Vec<u32>,
}

impl RuleSet {
    /// Compiles a config. `generation` is the snapshot's version number
    /// (bigger is newer); it is for display and logs, and the data plane
    /// applies whatever file it reads.
    pub fn compile(config: &Config, generation: u64) -> Result<RuleSet, RuleError> {
        let config = config.normalize()?;
        let mut rules = Vec::with_capacity(config.rules.len());
        let mut apps: Vec<String> = Vec::new();
        let (mut any, mut nets, mut domain_rules) = (Vec::new(), Vec::new(), Vec::new());
        let (mut exact_items, mut sub_items) = (Vec::new(), Vec::new());

        for (i, r) in config.rules.iter().enumerate() {
            let i = i as u32;
            let app = match &r.app {
                None => 0,
                Some(a) => {
                    let at = apps.iter().position(|x| x == a).unwrap_or_else(|| {
                        apps.push(a.clone());
                        apps.len() - 1
                    });
                    at as u32 + 1
                }
            };
            rules.push(Compiled {
                id: r.id,
                action: r.action,
                spec: specificity(r),
                app,
                transport: r.transport,
                ports: r.ports,
            });
            match &r.dest {
                Dest::Any => any.push(i),
                Dest::Domain(d) => {
                    exact_items.push((d.clone(), i));
                    domain_rules.push(i);
                }
                Dest::Subdomains(d) => {
                    sub_items.push((d.clone(), i));
                    domain_rules.push(i);
                }
                Dest::Cidr(addr, prefix) => nets.push(Net {
                    rule: i,
                    addr: *addr,
                    prefix: *prefix,
                }),
                Dest::Address(addr) => nets.push(Net {
                    rule: i,
                    addr: *addr,
                    prefix: addr_bits(*addr),
                }),
            }
        }
        Ok(RuleSet {
            mode: config.mode,
            panic: config.panic,
            essentials: config.essentials,
            generation,
            rules,
            apps,
            exact: DomainIndex::build(exact_items),
            subs: DomainIndex::build(sub_items),
            any,
            nets,
            domain_rules,
        })
    }

    /// No rules, allow-all.
    pub fn allow_all() -> RuleSet {
        // An empty default config always compiles.
        RuleSet::compile(&Config::default(), 0).unwrap_or_else(|_| unreachable!())
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn panic(&self) -> bool {
        self.panic
    }

    pub fn essentials(&self) -> bool {
        self.essentials
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn decide(&self, q: &Query<'_>) -> Decision {
        if self.panic {
            return Decision::Allow(Reason::Panic);
        }
        if self.mode == Mode::Lockdown {
            return Decision::Block(Reason::Lockdown);
        }
        let name: Option<Cow<'_, str>> = match q.name {
            NameState::Known(n) => Some(normalize_name(n)),
            NameState::Pending | NameState::Unavailable => None,
        };
        let best = self.best_match(q, name.as_deref());
        if matches!(q.name, NameState::Pending) && self.name_could_change(q, best) {
            return Decision::Wait;
        }
        match best {
            Some(c) => {
                let reason = Reason::Rule { id: c.id };
                match c.action {
                    Action::Allow => Decision::Allow(reason),
                    Action::Block => Decision::Block(reason),
                }
            }
            None => self.default_decision(q, name.as_deref()),
        }
    }

    /// The answer when no rule matched.
    fn default_decision(&self, q: &Query<'_>, name: Option<&str>) -> Decision {
        match self.mode {
            Mode::AllowAll => Decision::Allow(Reason::ModeDefault),
            Mode::BlockAll => {
                if self.essentials && essentials::is_essential(q.transport, q.port, name) {
                    Decision::Allow(Reason::Essential)
                } else {
                    Decision::Block(Reason::ModeDefault)
                }
            }
            Mode::Lockdown => Decision::Block(Reason::Lockdown),
        }
    }

    /// Whether learning the name could turn the answer into a different
    /// allow or block. `best` is the winner among rules that need no name.
    fn name_could_change(&self, q: &Query<'_>, best: Option<&Compiled>) -> bool {
        // What the connection gets if no name ever turns up.
        let current = match best {
            Some(c) => c.action,
            None => match self.default_decision(q, None) {
                Decision::Allow(_) => Action::Allow,
                _ => Action::Block,
            },
        };
        // Block-all with essentials: a name on the list would flip a block.
        if best.is_none()
            && self.mode == Mode::BlockAll
            && self.essentials
            && current == Action::Block
        {
            return true;
        }
        self.domain_rules.iter().any(|&i| {
            let d = &self.rules[i as usize];
            d.action != current && self.common_match(d, q) && best.is_none_or(|b| rank(d) > rank(b))
        })
    }

    /// The best rule that matches, using `name` for domain rules.
    fn best_match<'a>(&'a self, q: &Query<'_>, name: Option<&str>) -> Option<&'a Compiled> {
        let mut best: Option<&'a Compiled> = None;
        for &i in &self.any {
            self.offer(i, q, &mut best);
        }
        for n in &self.nets {
            if in_net(q.dst, n.addr, n.prefix) {
                self.offer(n.rule, q, &mut best);
            }
        }
        if let Some(name) = name {
            for i in self.exact.lookup(name) {
                self.offer(i, q, &mut best);
            }
            // Every proper suffix: a.b.c.com is tried as b.c.com, c.com, com.
            for (at, _) in name.match_indices('.') {
                for i in self.subs.lookup(&name[at + 1..]) {
                    self.offer(i, q, &mut best);
                }
            }
        }
        best
    }

    fn offer<'a>(&'a self, i: u32, q: &Query<'_>, best: &mut Option<&'a Compiled>) {
        let c = &self.rules[i as usize];
        if !self.common_match(c, q) {
            return;
        }
        if best.is_none_or(|b| rank(c) > rank(b)) {
            *best = Some(c);
        }
    }

    /// The parts of a match that do not depend on the destination.
    fn common_match(&self, c: &Compiled, q: &Query<'_>) -> bool {
        if c.app != 0 {
            let wanted = &self.apps[c.app as usize - 1];
            if !q.app.is_some_and(|a| a.id == *wanted) {
                return false;
            }
        }
        if c.transport.is_some_and(|t| t != q.transport) {
            return false;
        }
        c.ports.is_none_or(|p| (p.from..=p.to).contains(&q.port))
    }
}

/// Orders matching rules: higher wins.
fn rank(c: &Compiled) -> (u32, bool, Reverse<u32>) {
    (c.spec, c.action == Action::Block, Reverse(c.id))
}

fn specificity(r: &Rule) -> u32 {
    let (class, depth) = match &r.dest {
        Dest::Any => (0u32, 0u32),
        Dest::Cidr(_, prefix) => (1, u32::from(*prefix)),
        Dest::Subdomains(d) => (2, d.split('.').count() as u32),
        Dest::Domain(_) | Dest::Address(_) => (3, 0),
    };
    (u32::from(r.app.is_some()) << 20)
        | (class << 16)
        | (depth << 8)
        | (u32::from(r.ports.is_some()) << 1)
        | u32::from(r.transport.is_some())
}

fn normalize_name(name: &str) -> Cow<'_, str> {
    let trimmed = name.trim_end_matches('.');
    if trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(trimmed.to_ascii_lowercase())
    } else {
        Cow::Borrowed(trimmed)
    }
}

fn in_net(addr: IpAddr, net: IpAddr, prefix: u8) -> bool {
    match (addr, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let m = mask32(prefix);
            u32::from(a) & m == u32::from(n) & m
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let m = mask128(prefix);
            u128::from(a) & m == u128::from(n) & m
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: u32, action: Action, dest: Dest) -> Rule {
        Rule {
            id,
            action,
            dest,
            app: None,
            ports: None,
            transport: None,
        }
    }

    fn set(mode: Mode, rules: Vec<Rule>) -> RuleSet {
        RuleSet::compile(
            &Config {
                mode,
                panic: false,
                essentials: true,
                rules,
            },
            1,
        )
        .unwrap()
    }

    fn q(name: NameState<'_>) -> Query<'_> {
        Query {
            transport: Transport::Tcp,
            dst: "93.184.216.34".parse().unwrap(),
            port: 443,
            name,
            app: None,
        }
    }

    fn known(name: &str) -> NameState<'_> {
        NameState::Known(name)
    }

    fn blocked_by(d: Decision) -> Option<u32> {
        match d {
            Decision::Block(Reason::Rule { id }) => Some(id),
            _ => None,
        }
    }

    fn allowed_by(d: Decision) -> Option<u32> {
        match d {
            Decision::Allow(Reason::Rule { id }) => Some(id),
            _ => None,
        }
    }

    #[test]
    fn with_no_rules_the_mode_decides() {
        let allow = set(Mode::AllowAll, vec![]);
        assert_eq!(
            allow.decide(&q(known("x.test"))),
            Decision::Allow(Reason::ModeDefault)
        );
        let block = set(Mode::BlockAll, vec![]);
        assert_eq!(
            block.decide(&q(known("x.test"))),
            Decision::Block(Reason::ModeDefault)
        );
    }

    #[test]
    fn an_exact_domain_beats_a_wildcard() {
        let s = set(
            Mode::AllowAll,
            vec![
                rule(1, Action::Block, Dest::Subdomains("example.com".into())),
                rule(2, Action::Allow, Dest::Domain("ok.example.com".into())),
            ],
        );
        assert_eq!(allowed_by(s.decide(&q(known("ok.example.com")))), Some(2));
        assert_eq!(blocked_by(s.decide(&q(known("bad.example.com")))), Some(1));
        // A wildcard never matches its own apex.
        assert_eq!(
            s.decide(&q(known("example.com"))),
            Decision::Allow(Reason::ModeDefault)
        );
    }

    #[test]
    fn deeper_wildcards_and_longer_prefixes_win() {
        let s = set(
            Mode::AllowAll,
            vec![
                rule(1, Action::Block, Dest::Subdomains("example.com".into())),
                rule(2, Action::Allow, Dest::Subdomains("cdn.example.com".into())),
                rule(3, Action::Block, Dest::Cidr("93.0.0.0".parse().unwrap(), 8)),
                rule(
                    4,
                    Action::Allow,
                    Dest::Cidr("93.184.0.0".parse().unwrap(), 16),
                ),
            ],
        );
        assert_eq!(
            allowed_by(s.decide(&q(known("a.cdn.example.com")))),
            Some(2)
        );
        assert_eq!(blocked_by(s.decide(&q(known("www.example.com")))), Some(1));
        // The address rules, with no name in play: /16 beats /8.
        assert_eq!(allowed_by(s.decide(&q(NameState::Unavailable))), Some(4));
    }

    #[test]
    fn a_domain_beats_an_address_range() {
        let s = set(
            Mode::AllowAll,
            vec![
                rule(
                    1,
                    Action::Block,
                    Dest::Cidr("93.184.216.0".parse().unwrap(), 24),
                ),
                rule(2, Action::Allow, Dest::Subdomains("example.org".into())),
            ],
        );
        assert_eq!(allowed_by(s.decide(&q(known("www.example.org")))), Some(2));
    }

    #[test]
    fn an_app_rule_beats_a_destination_rule() {
        let app = AppId::new(flynn_types::Platform::Ios, "com.example.app");
        let mut r1 = rule(1, Action::Block, Dest::Any);
        r1.app = Some("com.example.app".into());
        let r2 = rule(2, Action::Allow, Dest::Domain("ok.test".into()));
        let s = set(Mode::AllowAll, vec![r1, r2]);
        let mut query = q(known("ok.test"));
        query.app = Some(&app);
        assert_eq!(blocked_by(s.decide(&query)), Some(1));
        // Another app, or an app that is not known, is not touched by it.
        let other = AppId::new(flynn_types::Platform::Ios, "com.other");
        query.app = Some(&other);
        assert_eq!(allowed_by(s.decide(&query)), Some(2));
        query.app = None;
        assert_eq!(allowed_by(s.decide(&query)), Some(2));
    }

    #[test]
    fn block_beats_allow_at_equal_specificity_and_the_lower_id_breaks_the_rest() {
        let s = set(
            Mode::AllowAll,
            vec![
                rule(7, Action::Allow, Dest::Domain("x.test".into())),
                rule(3, Action::Block, Dest::Domain("x.test".into())),
                rule(2, Action::Block, Dest::Domain("x.test".into())),
            ],
        );
        assert_eq!(blocked_by(s.decide(&q(known("x.test")))), Some(2));
    }

    #[test]
    fn ports_and_transports_narrow_a_rule() {
        let mut block_25 = rule(1, Action::Block, Dest::Any);
        block_25.ports = Some(PortRange { from: 25, to: 25 });
        let mut udp_only = rule(2, Action::Block, Dest::Any);
        udp_only.transport = Some(Transport::Udp);
        let s = set(Mode::AllowAll, vec![block_25, udp_only]);
        let mut query = q(NameState::Unavailable);
        assert!(matches!(s.decide(&query), Decision::Allow(_)));
        query.port = 25;
        assert_eq!(blocked_by(s.decide(&query)), Some(1));
        query.port = 443;
        query.transport = Transport::Udp;
        assert_eq!(blocked_by(s.decide(&query)), Some(2));
    }

    #[test]
    fn names_are_matched_without_regard_to_case_or_a_trailing_dot() {
        let s = set(
            Mode::AllowAll,
            vec![rule(1, Action::Block, Dest::Domain("tracker.test".into()))],
        );
        assert_eq!(blocked_by(s.decide(&q(known("Tracker.TEST.")))), Some(1));
    }

    #[test]
    fn panic_beats_lockdown_and_lockdown_beats_allow_rules() {
        let allow_rule = rule(1, Action::Allow, Dest::Any);
        let locked = set(Mode::Lockdown, vec![allow_rule.clone()]);
        assert_eq!(
            locked.decide(&q(known("x.test"))),
            Decision::Block(Reason::Lockdown)
        );
        let panicking = RuleSet::compile(
            &Config {
                mode: Mode::Lockdown,
                panic: true,
                essentials: true,
                rules: vec![rule(2, Action::Block, Dest::Any)],
            },
            1,
        )
        .unwrap();
        assert_eq!(
            panicking.decide(&q(known("x.test"))),
            Decision::Allow(Reason::Panic)
        );
    }

    #[test]
    fn block_all_keeps_the_essentials_but_a_user_rule_overrides_them() {
        let s = set(
            Mode::BlockAll,
            vec![rule(
                1,
                Action::Block,
                Dest::Domain("time.apple.com".into()),
            )],
        );
        // DNS, by port, whatever the name.
        let mut dns = q(NameState::Unavailable);
        dns.transport = Transport::Udp;
        dns.port = 53;
        assert_eq!(s.decide(&dns), Decision::Allow(Reason::Essential));
        // An essential name.
        assert_eq!(
            s.decide(&q(known("courier.push.apple.com"))),
            Decision::Allow(Reason::Essential)
        );
        // The user's own rule is stronger than the list.
        assert_eq!(blocked_by(s.decide(&q(known("time.apple.com")))), Some(1));
        // Anything else is blocked by default.
        assert_eq!(
            s.decide(&q(known("other.test"))),
            Decision::Block(Reason::ModeDefault)
        );
        // With the essentials off, even DNS goes.
        let off = RuleSet::compile(
            &Config {
                mode: Mode::BlockAll,
                panic: false,
                essentials: false,
                rules: vec![],
            },
            1,
        )
        .unwrap();
        assert_eq!(off.decide(&dns), Decision::Block(Reason::ModeDefault));
    }

    #[test]
    fn an_allow_rule_opens_a_hole_in_block_all() {
        let s = set(
            Mode::BlockAll,
            vec![rule(
                1,
                Action::Allow,
                Dest::Subdomains("example.com".into()),
            )],
        );
        assert_eq!(allowed_by(s.decide(&q(known("www.example.com")))), Some(1));
    }

    #[test]
    fn waiting_for_a_name_happens_only_when_a_name_could_matter() {
        // No domain rules and allow-all: nothing a name could change.
        let plain = set(Mode::AllowAll, vec![]);
        assert!(matches!(
            plain.decide(&q(NameState::Pending)),
            Decision::Allow(_)
        ));
        // A domain block rule: the name could block it.
        let blocking = set(
            Mode::AllowAll,
            vec![rule(1, Action::Block, Dest::Domain("x.test".into()))],
        );
        assert_eq!(blocking.decide(&q(NameState::Pending)), Decision::Wait);
        // ... but only on a port the rule covers.
        let mut port_rule = rule(1, Action::Block, Dest::Domain("x.test".into()));
        port_rule.ports = Some(PortRange { from: 25, to: 25 });
        let narrow = set(Mode::AllowAll, vec![port_rule]);
        assert!(matches!(
            narrow.decide(&q(NameState::Pending)),
            Decision::Allow(_)
        ));
        // A domain allow rule in allow-all changes nothing.
        let allowing = set(
            Mode::AllowAll,
            vec![rule(1, Action::Allow, Dest::Domain("x.test".into()))],
        );
        assert!(matches!(
            allowing.decide(&q(NameState::Pending)),
            Decision::Allow(_)
        ));
        // Block-all with essentials: a name on the list could allow it.
        let block_all = set(Mode::BlockAll, vec![]);
        assert_eq!(block_all.decide(&q(NameState::Pending)), Decision::Wait);
        // ... but DNS is allowed by port whatever the name.
        let mut dns = q(NameState::Pending);
        dns.transport = Transport::Udp;
        dns.port = 53;
        assert!(matches!(block_all.decide(&dns), Decision::Allow(_)));
        // And a higher-ranked rule that needs no name settles it at once.
        let settled = set(
            Mode::AllowAll,
            vec![
                rule(1, Action::Block, Dest::Any),
                rule(2, Action::Block, Dest::Subdomains("x.test".into())),
            ],
        );
        assert!(matches!(
            settled.decide(&q(NameState::Pending)),
            Decision::Block(_)
        ));
        // Once the name is known there is never a wait.
        assert!(matches!(
            blocking.decide(&q(known("y.test"))),
            Decision::Allow(_)
        ));
        assert!(matches!(
            blocking.decide(&q(NameState::Unavailable)),
            Decision::Allow(_)
        ));
    }

    #[test]
    fn many_rules_for_one_domain_are_all_considered() {
        let mut rules = Vec::new();
        for i in 0..50u32 {
            let mut r = rule(i + 1, Action::Block, Dest::Domain("busy.test".into()));
            r.ports = Some(PortRange {
                from: 1000 + i as u16,
                to: 1000 + i as u16,
            });
            rules.push(r);
        }
        let s = set(Mode::AllowAll, rules);
        let mut query = q(known("busy.test"));
        query.port = 1030;
        assert_eq!(blocked_by(s.decide(&query)), Some(31));
        query.port = 443;
        assert!(matches!(s.decide(&query), Decision::Allow(_)));
    }

    #[test]
    fn ipv6_ranges_match_only_ipv6() {
        let s = set(
            Mode::AllowAll,
            vec![rule(
                1,
                Action::Block,
                Dest::Cidr("2001:db8::".parse().unwrap(), 32),
            )],
        );
        let mut query = q(NameState::Unavailable);
        query.dst = "2001:db8:1::5".parse().unwrap();
        assert_eq!(blocked_by(s.decide(&query)), Some(1));
        query.dst = "2001:db9::5".parse().unwrap();
        assert!(matches!(s.decide(&query), Decision::Allow(_)));
        query.dst = "32.1.13.184".parse().unwrap(); // the same bits as IPv4
        assert!(matches!(s.decide(&query), Decision::Allow(_)));
    }
}
