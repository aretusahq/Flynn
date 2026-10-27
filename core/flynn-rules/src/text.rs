//! A small line-based text form of a rule set. Used for fixtures, the
//! harness `--rules` file and the debug screen's rules box, and the seed of
//! the shared filter syntax planned for v1.
//!
//! ```text
//! # comments start with a hash
//! mode block-all            # allow-all | block-all | lockdown
//! essentials on             # on | off
//! panic off                 # on | off
//! block subdomains tracker.test
//! allow domain www.example.com tcp port 443
//! allow cidr 10.0.0.0/8 app com.example.app
//! block address 203.0.113.9 udp
//! block any port 25
//! ```
//!
//! A rule is `allow` or `block`, then a destination (`any`, `domain NAME`,
//! `subdomains NAME`, `cidr ADDR/LEN`, `address ADDR`), then any of `app ID`,
//! `tcp`, `udp`, `port N` or `port N-M`, in any order. Rule ids are the
//! rules' positions in the text, counting from 1.

use std::fmt::{self, Write as _};
use std::net::IpAddr;

use crate::model::{Action, Config, Dest, Mode, PortRange, Rule};
use flynn_types::Transport;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// 1-based line number.
    pub line: usize,
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for ParseError {}

/// Parses the text form. The result is not yet normalised; compile or
/// encode it to validate names and ranges.
pub fn parse(text: &str) -> Result<Config, ParseError> {
    let mut config = Config::default();
    for (n, raw) in text.lines().enumerate() {
        let line_no = n + 1;
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let err = |message: String| ParseError {
            line: line_no,
            message,
        };
        let words: Vec<&str> = line.split_whitespace().collect();
        match words[0] {
            "mode" => {
                config.mode = match words.get(1).copied() {
                    Some("allow-all") => Mode::AllowAll,
                    Some("block-all") => Mode::BlockAll,
                    Some("lockdown") => Mode::Lockdown,
                    _ => return Err(err("mode is allow-all, block-all or lockdown".into())),
                };
                no_more(&words, 2).map_err(err)?;
            }
            "essentials" => {
                config.essentials = on_off(words.get(1).copied(), "essentials").map_err(err)?;
                no_more(&words, 2).map_err(err)?;
            }
            "panic" => {
                config.panic = on_off(words.get(1).copied(), "panic").map_err(err)?;
                no_more(&words, 2).map_err(err)?;
            }
            "allow" | "block" => {
                let action = if words[0] == "allow" {
                    Action::Allow
                } else {
                    Action::Block
                };
                let id = config.rules.len() as u32 + 1;
                config
                    .rules
                    .push(parse_rule(id, action, &words[1..]).map_err(err)?);
            }
            other => {
                return Err(err(format!(
                    "`{other}` is not a mode, essentials, panic, allow or block line"
                )));
            }
        }
    }
    Ok(config)
}

fn on_off(word: Option<&str>, what: &str) -> Result<bool, String> {
    match word {
        Some("on") => Ok(true),
        Some("off") => Ok(false),
        _ => Err(format!("{what} is on or off")),
    }
}

fn no_more(words: &[&str], used: usize) -> Result<(), String> {
    match words.get(used) {
        None => Ok(()),
        Some(extra) => Err(format!("unexpected `{extra}`")),
    }
}

fn parse_rule(id: u32, action: Action, words: &[&str]) -> Result<Rule, String> {
    let mut it = words.iter().copied();
    let dest = match it.next() {
        Some("any") => Dest::Any,
        Some("domain") => Dest::Domain(it.next().ok_or("domain needs a name")?.to_string()),
        Some("subdomains") => {
            Dest::Subdomains(it.next().ok_or("subdomains needs a name")?.to_string())
        }
        Some("address") => {
            let a = it.next().ok_or("address needs an IP address")?;
            Dest::Address(
                a.parse::<IpAddr>()
                    .map_err(|_| format!("`{a}` is not an IP address"))?,
            )
        }
        Some("cidr") => {
            let c = it.next().ok_or("cidr needs ADDRESS/LENGTH")?;
            let (addr, len) = c.split_once('/').ok_or("cidr needs ADDRESS/LENGTH")?;
            let addr = addr
                .parse::<IpAddr>()
                .map_err(|_| format!("`{addr}` is not an IP address"))?;
            let len = len
                .parse::<u8>()
                .map_err(|_| format!("`{len}` is not a prefix length"))?;
            Dest::Cidr(addr, len)
        }
        Some(other) => {
            return Err(format!(
                "`{other}` is not a destination (any, domain, subdomains, cidr or address)"
            ));
        }
        None => return Err("a rule needs a destination".into()),
    };
    let mut rule = Rule {
        id,
        action,
        dest,
        app: None,
        ports: None,
        transport: None,
    };
    while let Some(word) = it.next() {
        match word {
            "tcp" => set_once(&mut rule.transport, Transport::Tcp, "a transport")?,
            "udp" => set_once(&mut rule.transport, Transport::Udp, "a transport")?,
            "app" => {
                let id = it.next().ok_or("app needs an id")?;
                set_once(&mut rule.app, id.to_string(), "an app")?;
            }
            "port" => {
                let p = it.next().ok_or("port needs N or N-M")?;
                let range = match p.split_once('-') {
                    Some((a, b)) => PortRange {
                        from: a
                            .parse()
                            .map_err(|_| format!("`{p}` is not a port range"))?,
                        to: b
                            .parse()
                            .map_err(|_| format!("`{p}` is not a port range"))?,
                    },
                    None => {
                        let n: u16 = p.parse().map_err(|_| format!("`{p}` is not a port"))?;
                        PortRange { from: n, to: n }
                    }
                };
                set_once(&mut rule.ports, range, "a port")?;
            }
            other => return Err(format!("`{other}` is not app, tcp, udp or port")),
        }
    }
    Ok(rule)
}

fn set_once<T>(slot: &mut Option<T>, value: T, what: &str) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("{what} is given twice"));
    }
    *slot = Some(value);
    Ok(())
}

impl fmt::Display for Rule {
    /// The rule in the text form, without its id.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ",
            match self.action {
                Action::Allow => "allow",
                Action::Block => "block",
            }
        )?;
        match &self.dest {
            Dest::Any => write!(f, "any")?,
            Dest::Domain(d) => write!(f, "domain {d}")?,
            Dest::Subdomains(d) => write!(f, "subdomains {d}")?,
            Dest::Cidr(a, p) => write!(f, "cidr {a}/{p}")?,
            Dest::Address(a) => write!(f, "address {a}")?,
        }
        if let Some(app) = &self.app {
            write!(f, " app {app}")?;
        }
        match self.transport {
            Some(Transport::Tcp) => write!(f, " tcp")?,
            Some(Transport::Udp) => write!(f, " udp")?,
            None => {}
        }
        if let Some(p) = self.ports {
            if p.from == p.to {
                write!(f, " port {}", p.from)?;
            } else {
                write!(f, " port {}-{}", p.from, p.to)?;
            }
        }
        Ok(())
    }
}

impl Config {
    /// The text form. Parsing it back gives the same config when the rule ids
    /// are 1, 2, 3, ... in order.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "mode {}",
            match self.mode {
                Mode::AllowAll => "allow-all",
                Mode::BlockAll => "block-all",
                Mode::Lockdown => "lockdown",
            }
        );
        let _ = writeln!(
            out,
            "essentials {}",
            if self.essentials { "on" } else { "off" }
        );
        let _ = writeln!(out, "panic {}", if self.panic { "on" } else { "off" });
        for r in &self.rules {
            let _ = writeln!(out, "{r}");
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_form() {
        let c = parse(
            "# a comment\n\
             mode block-all\n\
             essentials off   # trailing comment\n\
             panic on\n\
             block subdomains tracker.test\n\
             allow domain www.example.com tcp port 443\n\
             allow cidr 10.0.0.0/8 app com.example.app\n\
             block address 203.0.113.9 udp\n\
             block any port 8000-8100\n",
        )
        .unwrap();
        assert_eq!(c.mode, Mode::BlockAll);
        assert!(!c.essentials);
        assert!(c.panic);
        assert_eq!(c.rules.len(), 5);
        assert_eq!(c.rules[1].id, 2);
        assert_eq!(c.rules[1].transport, Some(Transport::Tcp));
        assert_eq!(c.rules[1].ports, Some(PortRange { from: 443, to: 443 }));
        assert_eq!(c.rules[2].app.as_deref(), Some("com.example.app"));
        assert_eq!(
            c.rules[4].ports,
            Some(PortRange {
                from: 8000,
                to: 8100
            })
        );
    }

    #[test]
    fn clauses_may_come_in_any_order() {
        let a = parse("block domain x.test tcp port 25 app a.b").unwrap();
        let b = parse("block domain x.test app a.b port 25 tcp").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn errors_name_the_line() {
        for (text, line) in [
            ("mode sideways", 1),
            ("block any\nallow", 2),
            ("block domain", 1),
            ("allow cidr 10.0.0.0", 1),
            ("allow cidr 10.0.0.0/x", 1),
            ("allow address nope", 1),
            ("block any tcp tcp", 1),
            ("block any port 80 port 81", 1),
            ("block any port abc", 1),
            ("frobnicate", 1),
            ("panic maybe", 1),
            ("mode block-all extra", 1),
        ] {
            let e = parse(text).unwrap_err();
            assert_eq!(e.line, line, "{text:?}: {e}");
        }
    }

    #[test]
    fn text_round_trips() {
        let c = parse(
            "mode lockdown\nessentials off\nblock subdomains tracker.test\n\
             allow domain www.example.com tcp port 443\nallow cidr 10.0.0.0/8 app com.example.app\n\
             block address 2001:db8::1 udp port 1-1024\n",
        )
        .unwrap();
        assert_eq!(parse(&c.to_text()).unwrap(), c);
    }
}
