//! What a rule is, and how a set of rules is described before compiling.

use std::collections::HashSet;
use std::net::IpAddr;

use flynn_types::Transport;

/// The most rules one snapshot may hold.
pub const MAX_RULES: usize = 200_000;

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
    /// Block everything, essentials and allow rules included. Every attempt
    /// is still logged. Only the panic switch overrides it.
    Lockdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Block,
}

impl Action {
    pub fn verdict(self) -> Verdict {
        match self {
            Action::Allow => Verdict::Allow,
            Action::Block => Verdict::Block,
        }
    }
}

/// Where a rule applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dest {
    /// Any destination.
    Any,
    /// Exactly this name, and no other.
    Domain(String),
    /// Every subdomain of this name, at any depth, but not the name itself.
    Subdomains(String),
    /// A range of addresses. Normalising turns a full-length prefix into
    /// [`Dest::Address`].
    Cidr(IpAddr, u8),
    /// One address.
    Address(IpAddr),
}

/// An inclusive range of destination ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub from: u16,
    pub to: u16,
}

/// One rule. `id` is the caller's own number (a database row, say); it
/// names the rule in logs and breaks exact ties, so ids must be unique.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub id: u32,
    pub action: Action,
    pub dest: Dest,
    /// Only connections made by this app (its bundle ID or package name).
    /// Where the app is unknown, the rule does not match.
    pub app: Option<String>,
    pub ports: Option<PortRange>,
    pub transport: Option<Transport>,
}

/// Everything a snapshot holds: the rules and how they are applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub mode: Mode,
    /// Overrides everything, lockdown included, and allows all traffic.
    pub panic: bool,
    /// Whether block-all mode keeps the essentials list reachable.
    pub essentials: bool,
    pub rules: Vec<Rule>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::AllowAll,
            panic: false,
            essentials: true,
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuleError {
    #[error("rule {id}: {message}")]
    Invalid { id: u32, message: String },
    #[error("rule id {0} is used twice")]
    DuplicateId(u32),
    #[error("{0} rules is more than the limit of {MAX_RULES}")]
    TooMany(usize),
}

impl Config {
    /// The canonical form: names lowercased, address ranges masked to their
    /// prefix, and every rule checked. Everything that compiles, encodes or
    /// compares rules goes through this first.
    pub fn normalize(&self) -> Result<Config, RuleError> {
        if self.rules.len() > MAX_RULES {
            return Err(RuleError::TooMany(self.rules.len()));
        }
        let mut seen = HashSet::with_capacity(self.rules.len());
        let mut rules = Vec::with_capacity(self.rules.len());
        for rule in &self.rules {
            if !seen.insert(rule.id) {
                return Err(RuleError::DuplicateId(rule.id));
            }
            rules.push(rule.normalize()?);
        }
        Ok(Config {
            mode: self.mode,
            panic: self.panic,
            essentials: self.essentials,
            rules,
        })
    }
}

impl Rule {
    fn normalize(&self) -> Result<Rule, RuleError> {
        let bad = |message: &str| RuleError::Invalid {
            id: self.id,
            message: message.to_string(),
        };
        let dest = match &self.dest {
            Dest::Any => Dest::Any,
            Dest::Domain(d) => Dest::Domain(normalize_domain(d).map_err(|m| bad(&m))?),
            Dest::Subdomains(d) => Dest::Subdomains(normalize_domain(d).map_err(|m| bad(&m))?),
            Dest::Address(a) => Dest::Address(*a),
            Dest::Cidr(addr, prefix) => {
                let bits = addr_bits(*addr);
                if *prefix > bits {
                    return Err(bad("the prefix is longer than the address"));
                }
                if *prefix == bits {
                    Dest::Address(*addr)
                } else {
                    Dest::Cidr(mask_addr(*addr, *prefix), *prefix)
                }
            }
        };
        if let Some(p) = self.ports
            && (p.from == 0 || p.from > p.to)
        {
            return Err(bad("the port range must be 1 or more, and from <= to"));
        }
        if let Some(app) = &self.app
            && (app.is_empty() || app.len() > 255 || app.chars().any(char::is_control))
        {
            return Err(bad(
                "the app id is empty, too long or has control characters",
            ));
        }
        Ok(Rule {
            id: self.id,
            action: self.action,
            dest,
            app: self.app.clone(),
            ports: self.ports,
            transport: self.transport,
        })
    }
}

/// Lowercases a domain name, drops a trailing dot and checks it. Wildcards are
/// not part of a name; they are [`Dest::Subdomains`].
pub fn normalize_domain(name: &str) -> Result<String, String> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() {
        return Err("the domain is empty".into());
    }
    if name.len() > 253 {
        return Err("the domain is longer than 253 characters".into());
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("`{name}` has an empty or over-long label"));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(format!(
                "`{name}` has characters a name cannot (use a subdomains rule for wildcards)"
            ));
        }
    }
    Ok(name)
}

pub(crate) fn addr_bits(addr: IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// Zeroes the bits of `addr` beyond `prefix`.
pub(crate) fn mask_addr(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(a) => IpAddr::V4((u32::from(a) & mask32(prefix)).into()),
        IpAddr::V6(a) => IpAddr::V6((u128::from(a) & mask128(prefix)).into()),
    }
}

pub(crate) fn mask32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

pub(crate) fn mask128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: u32, dest: Dest) -> Rule {
        Rule {
            id,
            action: Action::Block,
            dest,
            app: None,
            ports: None,
            transport: None,
        }
    }

    fn config(rules: Vec<Rule>) -> Config {
        Config {
            rules,
            ..Config::default()
        }
    }

    #[test]
    fn domains_are_lowercased_and_stripped_of_the_trailing_dot() {
        let c = config(vec![rule(1, Dest::Domain("WWW.Example.COM.".into()))])
            .normalize()
            .unwrap();
        assert_eq!(c.rules[0].dest, Dest::Domain("www.example.com".into()));
    }

    #[test]
    fn bad_domains_are_rejected() {
        for bad in ["", "a..b", "*.example.com", "exa mple.com", &"a".repeat(64)] {
            let r = config(vec![rule(1, Dest::Domain(bad.into()))]).normalize();
            assert!(r.is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn address_ranges_are_masked_and_full_prefixes_become_addresses() {
        let c = config(vec![
            rule(1, Dest::Cidr("10.1.2.3".parse().unwrap(), 8)),
            rule(2, Dest::Cidr("192.0.2.7".parse().unwrap(), 32)),
            rule(3, Dest::Cidr("2001:db8::1".parse().unwrap(), 32)),
        ])
        .normalize()
        .unwrap();
        assert_eq!(c.rules[0].dest, Dest::Cidr("10.0.0.0".parse().unwrap(), 8));
        assert_eq!(c.rules[1].dest, Dest::Address("192.0.2.7".parse().unwrap()));
        assert_eq!(
            c.rules[2].dest,
            Dest::Cidr("2001:db8::".parse().unwrap(), 32)
        );
    }

    #[test]
    fn a_prefix_longer_than_the_address_is_rejected() {
        let r = config(vec![rule(1, Dest::Cidr("10.0.0.0".parse().unwrap(), 33))]).normalize();
        assert!(matches!(r, Err(RuleError::Invalid { id: 1, .. })));
    }

    #[test]
    fn ids_must_be_unique_and_ports_sane() {
        let dup = config(vec![rule(4, Dest::Any), rule(4, Dest::Any)]).normalize();
        assert_eq!(dup, Err(RuleError::DuplicateId(4)));
        let mut r = rule(1, Dest::Any);
        r.ports = Some(PortRange { from: 90, to: 80 });
        assert!(config(vec![r.clone()]).normalize().is_err());
        r.ports = Some(PortRange { from: 0, to: 80 });
        assert!(config(vec![r]).normalize().is_err());
    }

    #[test]
    fn normalizing_twice_changes_nothing() {
        let c = config(vec![
            rule(1, Dest::Subdomains("Tracker.TEST".into())),
            rule(2, Dest::Cidr("10.9.9.9".parse().unwrap(), 16)),
        ]);
        let once = c.normalize().unwrap();
        assert_eq!(once.normalize().unwrap(), once);
    }
}
