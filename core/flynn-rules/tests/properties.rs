//! Property tests for the rule engine.
//!
//! The main one is differential: a deliberately naive reference (scan every
//! rule, compare tuples) must agree with the indexed engine on random rule
//! sets over small pools of names, addresses and ports, which makes the
//! rules overlap constantly. The others check what the design promises:
//! rule order does not matter, a "final" answer while waiting for a name
//! holds for every name, and the snapshot and text forms round-trip.

use std::cmp::Reverse;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use flynn_rules::snapshot;
use flynn_rules::{
    Action, AppId, Config, Decision, Dest, ESSENTIAL_EXACT, ESSENTIAL_SUBDOMAINS, Mode, NameState,
    PortRange, Query, Reason, Rule, RuleSet, Transport,
};
use flynn_types::Platform;
use proptest::prelude::*;

// ----- Generators ---------------------------------------------------------

const LABELS: &[&str] = &[
    "a", "b", "c", "www", "cdn", "example", "tracker", "test", "com",
];
const APPS: &[&str] = &["app1", "app2"];
const PORTS: &[u16] = &[22, 25, 53, 80, 443, 853, 8080];

fn name() -> impl Strategy<Value = String> {
    prop::collection::vec(prop::sample::select(LABELS), 1..=4).prop_map(|v| v.join("."))
}

fn addr() -> impl Strategy<Value = IpAddr> {
    prop_oneof![
        (0u8..4, 0u8..4).prop_map(|(a, b)| IpAddr::V4(Ipv4Addr::new(10, a, b, 1))),
        (0u16..3).prop_map(|x| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, x, 0, 0, 0, 0, 1))),
    ]
}

fn bits(a: IpAddr) -> u8 {
    match a {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn dest() -> impl Strategy<Value = Dest> {
    prop_oneof![
        2 => Just(Dest::Any),
        3 => name().prop_map(Dest::Domain),
        3 => name().prop_map(Dest::Subdomains),
        2 => (addr(), 0u8..=128).prop_map(|(a, p)| Dest::Cidr(a, p % (bits(a) + 1))),
        1 => addr().prop_map(Dest::Address),
    ]
}

fn ports() -> impl Strategy<Value = Option<PortRange>> {
    prop_oneof![
        3 => Just(None),
        1 => (prop::sample::select(PORTS), 0u16..3)
            .prop_map(|(p, w)| Some(PortRange { from: p, to: p + w })),
    ]
}

fn transport() -> impl Strategy<Value = Option<Transport>> {
    prop_oneof![
        3 => Just(None),
        1 => Just(Some(Transport::Tcp)),
        1 => Just(Some(Transport::Udp)),
    ]
}

fn app() -> impl Strategy<Value = Option<String>> {
    prop_oneof![
        3 => Just(None),
        1 => prop::sample::select(APPS).prop_map(|a| Some(a.to_string())),
    ]
}

fn rule_body() -> impl Strategy<
    Value = (
        Action,
        Dest,
        Option<String>,
        Option<PortRange>,
        Option<Transport>,
    ),
> {
    (
        prop_oneof![Just(Action::Allow), Just(Action::Block)],
        dest(),
        app(),
        ports(),
        transport(),
    )
}

fn rules() -> impl Strategy<Value = Vec<Rule>> {
    prop::collection::vec(rule_body(), 0..8).prop_map(|bodies| {
        bodies
            .into_iter()
            .enumerate()
            .map(|(i, (action, dest, app, ports, transport))| Rule {
                id: i as u32 + 1,
                action,
                dest,
                app,
                ports,
                transport,
            })
            .collect()
    })
}

fn mode() -> impl Strategy<Value = Mode> {
    prop_oneof![
        3 => Just(Mode::AllowAll),
        3 => Just(Mode::BlockAll),
        1 => Just(Mode::Lockdown),
    ]
}

fn config() -> impl Strategy<Value = Config> {
    (
        mode(),
        prop_oneof![7 => Just(false), 1 => Just(true)],
        any::<bool>(),
        rules(),
    )
        .prop_map(|(mode, panic, essentials, rules)| Config {
            mode,
            panic,
            essentials,
            rules,
        })
}

#[derive(Debug, Clone)]
struct Probe {
    transport: Transport,
    dst: IpAddr,
    port: u16,
    app: Option<&'static str>,
}

fn probe() -> impl Strategy<Value = Probe> {
    (
        prop_oneof![Just(Transport::Tcp), Just(Transport::Udp)],
        prop_oneof![addr(), Just("192.0.2.1".parse().unwrap())],
        prop_oneof![prop::sample::select(PORTS), 1u16..65535],
        prop_oneof![Just(None), prop::sample::select(APPS).prop_map(Some)],
    )
        .prop_map(|(transport, dst, port, app)| Probe {
            transport,
            dst,
            port,
            app,
        })
}

fn query<'a>(p: &Probe, app: &'a Option<AppId>, name: NameState<'a>) -> Query<'a> {
    Query {
        transport: p.transport,
        dst: p.dst,
        port: p.port,
        name,
        app: app.as_ref(),
    }
}

fn app_id(p: &Probe) -> Option<AppId> {
    p.app.map(|a| AppId::new(Platform::Ios, a))
}

// ----- The reference ------------------------------------------------------

fn ref_in_net(addr: IpAddr, net: IpAddr, prefix: u8) -> bool {
    fn to_bits(a: IpAddr) -> Vec<bool> {
        let bytes = match a {
            IpAddr::V4(a) => a.octets().to_vec(),
            IpAddr::V6(a) => a.octets().to_vec(),
        };
        bytes
            .iter()
            .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1 == 1))
            .collect()
    }
    let (a, n) = (to_bits(addr), to_bits(net));
    a.len() == n.len() && a[..usize::from(prefix)] == n[..usize::from(prefix)]
}

fn ref_matches(r: &Rule, q: &Query<'_>, name: Option<&str>) -> bool {
    if let Some(want) = &r.app
        && q.app.map(|a| &a.id) != Some(want)
    {
        return false;
    }
    if r.transport.is_some_and(|t| t != q.transport) {
        return false;
    }
    if let Some(p) = r.ports
        && !(p.from <= q.port && q.port <= p.to)
    {
        return false;
    }
    match &r.dest {
        Dest::Any => true,
        Dest::Domain(d) => name == Some(d.as_str()),
        Dest::Subdomains(d) => name.is_some_and(|n| n.ends_with(&format!(".{d}"))),
        Dest::Cidr(a, p) => ref_in_net(q.dst, *a, *p),
        Dest::Address(a) => q.dst == *a,
    }
}

type Rank = (bool, u8, u32, bool, bool, bool, Reverse<u32>);

fn ref_rank(r: &Rule) -> Rank {
    let (class, depth) = match &r.dest {
        Dest::Any => (0, 0),
        Dest::Cidr(_, p) => (1, u32::from(*p)),
        Dest::Subdomains(d) => (2, d.split('.').count() as u32),
        Dest::Domain(_) | Dest::Address(_) => (3, 0),
    };
    (
        r.app.is_some(),
        class,
        depth,
        r.ports.is_some(),
        r.transport.is_some(),
        r.action == Action::Block,
        Reverse(r.id),
    )
}

fn ref_essential(q: &Query<'_>, name: Option<&str>) -> bool {
    let dns = matches!(
        (q.transport, q.port),
        (Transport::Udp, 53) | (Transport::Tcp, 53) | (Transport::Tcp, 853)
    );
    dns || name.is_some_and(|n| {
        ESSENTIAL_EXACT.contains(&n)
            || ESSENTIAL_SUBDOMAINS
                .iter()
                .any(|s| n == *s || n.ends_with(&format!(".{s}")))
    })
}

/// The decision for a known or unavailable name, by plain scanning.
fn ref_decide(config: &Config, q: &Query<'_>, name: Option<&str>) -> Decision {
    if config.panic {
        return Decision::Allow(Reason::Panic);
    }
    if config.mode == Mode::Lockdown {
        return Decision::Block(Reason::Lockdown);
    }
    let best = config
        .rules
        .iter()
        .filter(|r| ref_matches(r, q, name))
        .max_by_key(|r| ref_rank(r));
    match best {
        Some(r) => match r.action {
            Action::Allow => Decision::Allow(Reason::Rule { id: r.id }),
            Action::Block => Decision::Block(Reason::Rule { id: r.id }),
        },
        None => match config.mode {
            Mode::AllowAll => Decision::Allow(Reason::ModeDefault),
            Mode::BlockAll if config.essentials && ref_essential(q, name) => {
                Decision::Allow(Reason::Essential)
            }
            _ => Decision::Block(Reason::ModeDefault),
        },
    }
}

/// Names worth trying: the ones the rules mention, names under their
/// wildcards, essentials, and strangers.
fn candidate_names(config: &Config) -> Vec<String> {
    let mut names = vec![
        "other.test".to_string(),
        "time.apple.com".to_string(),
        "courier.push.apple.com".to_string(),
        "a.b.c.com".to_string(),
    ];
    for r in &config.rules {
        match &r.dest {
            Dest::Domain(d) => names.push(d.clone()),
            Dest::Subdomains(d) => {
                names.push(format!("x.{d}"));
                names.push(format!("x.y.{d}"));
            }
            _ => {}
        }
    }
    names
}

// ----- Properties ---------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3000))]

    /// The indexed engine and the naive reference give the same decision
    /// for every query whose name is known or unavailable.
    #[test]
    fn engine_matches_the_reference(
        config in config(),
        probe in probe(),
        picked in prop::sample::select(vec![
            "a", "a.b", "www.example.com", "cdn.example.com", "tracker.test", "x.tracker.test",
            "time.apple.com", "courier.push.apple.com", "other.test", "",
        ]),
    ) {
        let normalized = config.normalize().unwrap();
        let engine = RuleSet::compile(&config, 1).unwrap();
        let app = app_id(&probe);
        // Every rule's own names, so exact and wildcard rules are hit often.
        let mut names = candidate_names(&normalized);
        names.push(picked.to_string());
        for n in &names {
            if n.is_empty() { continue; }
            let got = engine.decide(&query(&probe, &app, NameState::Known(n)));
            prop_assert_eq!(got, ref_decide(&normalized, &query(&probe, &app, NameState::Known(n)), Some(n)),
                "name {}", n);
        }
        let got = engine.decide(&query(&probe, &app, NameState::Unavailable));
        prop_assert_eq!(got, ref_decide(&normalized, &query(&probe, &app, NameState::Unavailable), None));
    }

    /// Names are matched without regard to case or a trailing dot.
    #[test]
    fn names_are_normalised(config in config(), probe in probe(), n in name()) {
        let engine = RuleSet::compile(&config, 1).unwrap();
        let app = app_id(&probe);
        let plain = engine.decide(&query(&probe, &app, NameState::Known(&n)));
        let shouted = format!("{}.", n.to_ascii_uppercase());
        prop_assert_eq!(engine.decide(&query(&probe, &app, NameState::Known(&shouted))), plain);
    }

    /// The order the rules are listed in changes nothing, down to which rule
    /// is named as the reason.
    #[test]
    fn rule_order_does_not_matter(
        (config, shuffled) in (config(), any::<u64>()).prop_map(|(c, seed)| {
            let mut s = c.clone();
            // A deterministic shuffle from the seed.
            let n = s.rules.len();
            if n > 1 {
                let mut state = seed | 1;
                for i in (1..n).rev() {
                    state ^= state << 13; state ^= state >> 7; state ^= state << 17;
                    s.rules.swap(i, (state % (i as u64 + 1)) as usize);
                }
            }
            (c, s)
        }),
        probe in probe(),
    ) {
        let a = RuleSet::compile(&config, 1).unwrap();
        let b = RuleSet::compile(&shuffled, 1).unwrap();
        let app = app_id(&probe);
        for state in [NameState::Unavailable, NameState::Pending, NameState::Known("www.example.com"), NameState::Known("x.tracker.test")] {
            prop_assert_eq!(a.decide(&query(&probe, &app, state)), b.decide(&query(&probe, &app, state)));
        }
    }

    /// If the engine does not say "wait", no name can change the answer.
    /// (It may wait when none could, for instance when a more specific rule
    /// of the other action always covers the same names; that costs a short
    /// hold, never a wrong answer, so only soundness is asserted.)
    #[test]
    fn a_final_answer_while_pending_holds_for_every_name(config in config(), probe in probe()) {
        let normalized = config.normalize().unwrap();
        let engine = RuleSet::compile(&config, 1).unwrap();
        let app = app_id(&probe);
        let pending = engine.decide(&query(&probe, &app, NameState::Pending));
        let unnamed = engine.decide(&query(&probe, &app, NameState::Unavailable));
        let names = candidate_names(&normalized);
        let verdicts: Vec<_> = names
            .iter()
            .map(|n| engine.decide(&query(&probe, &app, NameState::Known(n))).verdict())
            .collect();
        if pending != Decision::Wait {
            prop_assert_eq!(pending.verdict(), unnamed.verdict());
            for (n, v) in names.iter().zip(&verdicts) {
                prop_assert_eq!(*v, pending.verdict(), "name {}", n);
            }
        }
    }

    /// Panic allows everything, whatever else the config says.
    #[test]
    fn panic_allows_everything(mut config in config(), probe in probe()) {
        config.panic = true;
        let engine = RuleSet::compile(&config, 1).unwrap();
        let app = app_id(&probe);
        for state in [NameState::Pending, NameState::Unavailable, NameState::Known("tracker.test")] {
            prop_assert_eq!(engine.decide(&query(&probe, &app, state)), Decision::Allow(Reason::Panic));
        }
    }

    /// Lockdown blocks everything unless panic is on.
    #[test]
    fn lockdown_blocks_everything(mut config in config(), probe in probe()) {
        config.mode = Mode::Lockdown;
        config.panic = false;
        let engine = RuleSet::compile(&config, 1).unwrap();
        let app = app_id(&probe);
        for state in [NameState::Pending, NameState::Unavailable, NameState::Known("www.example.com")] {
            prop_assert_eq!(engine.decide(&query(&probe, &app, state)), Decision::Block(Reason::Lockdown));
        }
    }

    #[test]
    fn snapshots_round_trip(config in config(), generation in any::<u64>()) {
        let bytes = snapshot::encode(&config, generation).unwrap();
        let back = snapshot::decode(&bytes).unwrap();
        prop_assert_eq!(back.generation, generation);
        prop_assert_eq!(back.config, config.normalize().unwrap());
    }

    #[test]
    fn the_text_form_round_trips(config in config()) {
        let normalized = config.normalize().unwrap();
        let parsed = flynn_rules::text::parse(&normalized.to_text()).unwrap();
        prop_assert_eq!(parsed, normalized);
    }

    /// Whatever the bytes, decoding returns an error or a snapshot; it never
    /// panics, and a mutated snapshot is never accepted as the original.
    #[test]
    fn decoding_hostile_bytes_is_safe(
        config in config(),
        flips in prop::collection::vec((any::<usize>(), 1u8..=255), 1..4),
        cut in any::<usize>(),
        junk in prop::collection::vec(any::<u8>(), 0..200),
    ) {
        let original = snapshot::encode(&config, 9).unwrap();
        let mut mutated = original.clone();
        for (at, xor) in flips {
            let i = at % mutated.len();
            mutated[i] ^= xor;
        }
        if mutated != original
            && let Ok(s) = snapshot::decode(&mutated)
        {
            // Possible only if the flips cancelled out in the checksum.
            prop_assert_ne!(Some(s.config), snapshot::decode(&original).ok().map(|o| o.config));
        }
        let _ = snapshot::decode(&original[..cut % (original.len() + 1)]);
        let _ = snapshot::decode(&junk);
    }
}
