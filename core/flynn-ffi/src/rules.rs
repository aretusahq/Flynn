//! Rules for the app: build a set, write it as the snapshot the capture
//! extension loads, and check what is on disk. The extension side (loading
//! and reloading) is on `FlynnDataPlane`.

use std::fs;
use std::io::Write as _;
use std::net::IpAddr;
use std::path::Path;

use flynn_rules as rules;
use flynn_rules::{Action, Mode, snapshot, text};
use flynn_types::Transport;

use crate::FlynnError;

/// Where a rule applies. Addresses are text ("10.0.0.0", "2001:db8::").
#[derive(Debug, Clone, uniffi::Enum)]
pub enum RuleDest {
    Any,
    /// Exactly this name.
    Domain {
        name: String,
    },
    /// Every subdomain of this name, but not the name itself.
    Subdomains {
        suffix: String,
    },
    Cidr {
        address: String,
        prefix: u8,
    },
    Address {
        address: String,
    },
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct RuleSpec {
    /// Unique. Names the rule in logs ("blocked by rule 12").
    pub id: u32,
    pub action: Action,
    pub dest: RuleDest,
    /// Only connections made by this app. Unknown apps never match.
    pub app: Option<String>,
    pub port_from: Option<u16>,
    pub port_to: Option<u16>,
    pub transport: Option<Transport>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct RulesConfig {
    pub mode: Mode,
    /// Allows everything, lockdown included.
    pub panic: bool,
    /// Whether block-all keeps DNS, push, captive-portal checks, time and
    /// certificate revocation reachable.
    pub essentials: bool,
    pub rules: Vec<RuleSpec>,
}

/// What a loaded rule set looks like, for the debug screen and the logs.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RulesInfo {
    pub generation: u64,
    pub rule_count: u32,
    pub mode: Mode,
    pub panic: bool,
    pub essentials: bool,
}

pub(crate) fn info_of(rules: &rules::RuleSet) -> RulesInfo {
    RulesInfo {
        generation: rules.generation(),
        rule_count: rules.rule_count() as u32,
        mode: rules.mode(),
        panic: rules.panic(),
        essentials: rules.essentials(),
    }
}

fn invalid(message: impl Into<String>) -> FlynnError {
    FlynnError::InvalidRules {
        message: message.into(),
    }
}

impl TryFrom<RulesConfig> for rules::Config {
    type Error = FlynnError;

    fn try_from(c: RulesConfig) -> Result<Self, FlynnError> {
        let addr = |id: u32, s: &str| -> Result<IpAddr, FlynnError> {
            s.parse()
                .map_err(|_| invalid(format!("rule {id}: `{s}` is not an IP address")))
        };
        let mut out = Vec::with_capacity(c.rules.len());
        for r in c.rules {
            let dest = match &r.dest {
                RuleDest::Any => rules::Dest::Any,
                RuleDest::Domain { name } => rules::Dest::Domain(name.clone()),
                RuleDest::Subdomains { suffix } => rules::Dest::Subdomains(suffix.clone()),
                RuleDest::Cidr { address, prefix } => {
                    rules::Dest::Cidr(addr(r.id, address)?, *prefix)
                }
                RuleDest::Address { address } => rules::Dest::Address(addr(r.id, address)?),
            };
            let ports = match (r.port_from, r.port_to) {
                (None, None) => None,
                (Some(from), None) => Some(rules::PortRange { from, to: from }),
                (Some(from), Some(to)) => Some(rules::PortRange { from, to }),
                (None, Some(_)) => {
                    return Err(invalid(format!(
                        "rule {}: a port range needs a start",
                        r.id
                    )));
                }
            };
            out.push(rules::Rule {
                id: r.id,
                action: r.action,
                dest,
                app: r.app,
                ports,
                transport: r.transport,
            });
        }
        Ok(rules::Config {
            mode: c.mode,
            panic: c.panic,
            essentials: c.essentials,
            rules: out,
        })
    }
}

impl From<rules::Config> for RulesConfig {
    fn from(c: rules::Config) -> Self {
        RulesConfig {
            mode: c.mode,
            panic: c.panic,
            essentials: c.essentials,
            rules: c
                .rules
                .into_iter()
                .map(|r| {
                    let dest = match r.dest {
                        rules::Dest::Any => RuleDest::Any,
                        rules::Dest::Domain(name) => RuleDest::Domain { name },
                        rules::Dest::Subdomains(suffix) => RuleDest::Subdomains { suffix },
                        rules::Dest::Cidr(a, prefix) => RuleDest::Cidr {
                            address: a.to_string(),
                            prefix,
                        },
                        rules::Dest::Address(a) => RuleDest::Address {
                            address: a.to_string(),
                        },
                    };
                    RuleSpec {
                        id: r.id,
                        action: r.action,
                        dest,
                        app: r.app,
                        port_from: r.ports.map(|p| p.from),
                        port_to: r.ports.map(|p| p.to),
                        transport: r.transport,
                    }
                })
                .collect(),
        }
    }
}

/// Validates `config` and writes it as the snapshot at `path`, atomically:
/// to a temporary file in the same folder, then renamed over the old one, so
/// the extension reads the old rules or the new ones, never half of each.
/// `generation` is the version number; use something that grows, like the
/// time in milliseconds.
#[uniffi::export]
pub fn write_rule_snapshot(
    path: String,
    config: RulesConfig,
    generation: u64,
) -> Result<(), FlynnError> {
    let config = rules::Config::try_from(config)?;
    let bytes = snapshot::encode(&config, generation).map_err(|e| invalid(e.to_string()))?;
    let path = Path::new(&path);
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

/// What the snapshot at `path` holds, or `None` if there is no file. An
/// error if it is damaged: the extension would refuse it too.
#[uniffi::export]
pub fn read_rules_info(path: String) -> Result<Option<RulesInfo>, FlynnError> {
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let snap = snapshot::decode(&bytes).map_err(|e| invalid(e.to_string()))?;
    let set = snap.compile().map_err(|e| invalid(e.to_string()))?;
    Ok(Some(info_of(&set)))
}

/// Parses the text form of a rule set (see docs/rules.md). Errors name the
/// line.
#[uniffi::export]
pub fn parse_rules_text(text: String) -> Result<RulesConfig, FlynnError> {
    let config = text::parse(&text).map_err(|e| invalid(e.to_string()))?;
    // Check names and ranges now, so a typo shows up where it was typed.
    config.normalize().map_err(|e| invalid(e.to_string()))?;
    Ok(config.into())
}

/// The text form of a rule set.
#[uniffi::export]
pub fn rules_to_text(config: RulesConfig) -> Result<String, FlynnError> {
    Ok(rules::Config::try_from(config)?.to_text())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("flynn-ffi-rules-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn text_becomes_a_config_and_back() {
        let c =
            parse_rules_text("mode block-all\nblock subdomains tracker.test tcp port 443\n".into())
                .unwrap();
        assert_eq!(c.mode, Mode::BlockAll);
        assert_eq!(c.rules.len(), 1);
        assert_eq!(
            (c.rules[0].port_from, c.rules[0].port_to),
            (Some(443), Some(443))
        );
        let text = rules_to_text(c).unwrap();
        assert!(text.contains("block subdomains tracker.test tcp port 443"));
    }

    #[test]
    fn mistakes_are_reported_with_the_line() {
        let e = parse_rules_text("block any\nblock domain bad name\n".into()).unwrap_err();
        assert!(e.to_string().contains("line 2"), "{e}");
        let e = parse_rules_text("block domain a..b\n".into()).unwrap_err();
        assert!(e.to_string().contains("rule 1"), "{e}");
    }

    #[test]
    fn a_snapshot_is_written_atomically_and_read_back() {
        let dir = tmpdir("write");
        let path = dir
            .join("nested/rules.snapshot")
            .to_string_lossy()
            .into_owned();
        assert_eq!(read_rules_info(path.clone()).unwrap(), None);

        let config = parse_rules_text("mode lockdown\npanic on\nblock any\n".into()).unwrap();
        write_rule_snapshot(path.clone(), config, 77).unwrap();
        let info = read_rules_info(path.clone()).unwrap().unwrap();
        assert_eq!(
            info,
            RulesInfo {
                generation: 77,
                rule_count: 1,
                mode: Mode::Lockdown,
                panic: true,
                essentials: true
            }
        );
        // No temporary file is left behind.
        assert!(!Path::new(&path).with_extension("tmp").exists());

        // A rewrite replaces it; a damaged file is an error, not silence.
        write_rule_snapshot(path.clone(), parse_rules_text(String::new()).unwrap(), 78).unwrap();
        assert_eq!(
            read_rules_info(path.clone()).unwrap().unwrap().rule_count,
            0
        );
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        fs::write(&path, bytes).unwrap();
        assert!(read_rules_info(path).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn bad_addresses_and_port_ranges_are_refused() {
        let mut c = parse_rules_text("block any\n".into()).unwrap();
        c.rules[0].dest = RuleDest::Cidr {
            address: "not-an-ip".into(),
            prefix: 8,
        };
        assert!(rules::Config::try_from(c.clone()).is_err());
        c.rules[0].dest = RuleDest::Any;
        c.rules[0].port_to = Some(80);
        assert!(rules::Config::try_from(c).is_err());
    }

    #[test]
    fn a_single_port_needs_only_a_start() {
        let mut c = parse_rules_text("block any\n".into()).unwrap();
        c.rules[0].port_from = Some(25);
        let config = rules::Config::try_from(c).unwrap();
        assert_eq!(
            config.rules[0].ports,
            Some(rules::PortRange { from: 25, to: 25 })
        );
        assert_eq!(config.rules[0].action, Action::Block);
        let _ = Transport::Tcp;
    }
}
