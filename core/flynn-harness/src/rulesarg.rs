//! Building a rule set from the harness's command line: a rules file in the
//! text form (see docs/rules.md), with flags layered on top.

use std::path::PathBuf;
use std::sync::Arc;

use flynn_dataplane::RulesPolicy;
use flynn_rules::{Action, Config, Dest, Mode, Rule, RuleSet, text};

#[derive(Clone, Default)]
pub struct RulesArgs {
    /// `--rules FILE`. In live mode the file is re-read whenever it changes.
    pub file: Option<PathBuf>,
    /// `--mode allow-all|block-all|lockdown`, overriding the file's.
    pub mode: Option<Mode>,
    /// `--block DOMAIN`: the domain and everything under it.
    pub block: Vec<String>,
    /// `--allow DOMAIN`: the domain and everything under it.
    pub allow: Vec<String>,
    /// `--no-essentials`
    pub no_essentials: bool,
    /// `--panic`
    pub panic: bool,
}

pub fn parse_mode(s: &str) -> Result<Mode, String> {
    match s {
        "allow-all" => Ok(Mode::AllowAll),
        "block-all" => Ok(Mode::BlockAll),
        "lockdown" => Ok(Mode::Lockdown),
        other => Err(format!(
            "`{other}` is not a mode (allow-all, block-all or lockdown)"
        )),
    }
}

impl RulesArgs {
    /// The file first, then the flags on top.
    pub fn config(&self) -> Result<Config, String> {
        let mut config = match &self.file {
            Some(path) => {
                let text_form = std::fs::read_to_string(path)
                    .map_err(|e| format!("{}: {e}", path.display()))?;
                text::parse(&text_form).map_err(|e| format!("{}: {e}", path.display()))?
            }
            None => Config::default(),
        };
        if let Some(mode) = self.mode {
            config.mode = mode;
        }
        if self.no_essentials {
            config.essentials = false;
        }
        if self.panic {
            config.panic = true;
        }
        for (action, domains) in [(Action::Block, &self.block), (Action::Allow, &self.allow)] {
            for domain in domains {
                for dest in [
                    Dest::Domain(domain.clone()),
                    Dest::Subdomains(domain.clone()),
                ] {
                    let id = config.rules.iter().map(|r| r.id).max().unwrap_or(0) + 1;
                    config.rules.push(Rule {
                        id,
                        action,
                        dest,
                        app: None,
                        ports: None,
                        transport: None,
                    });
                }
            }
        }
        Ok(config)
    }

    pub fn rule_set(&self, generation: u64) -> Result<RuleSet, String> {
        RuleSet::compile(&self.config()?, generation).map_err(|e| e.to_string())
    }

    pub fn policy(&self) -> Result<Arc<RulesPolicy>, String> {
        Ok(Arc::new(RulesPolicy::new(self.rule_set(1)?)))
    }
}

/// One line for the start-up banner and for reload messages.
pub fn summary(set: &RuleSet) -> String {
    format!(
        "{} rules, mode {}{}{}",
        set.rule_count(),
        match set.mode() {
            Mode::AllowAll => "allow-all",
            Mode::BlockAll => "block-all",
            Mode::Lockdown => "lockdown",
        },
        if set.essentials() {
            ""
        } else {
            ", essentials off"
        },
        if set.panic() {
            ", PANIC (everything allowed)"
        } else {
            ""
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_layer_on_top_of_nothing() {
        let args = RulesArgs {
            block: vec!["a.test".into()],
            allow: vec!["b.test".into()],
            mode: Some(Mode::BlockAll),
            ..RulesArgs::default()
        };
        let c = args.config().unwrap();
        assert_eq!(c.mode, Mode::BlockAll);
        assert_eq!(c.rules.len(), 4);
        assert_eq!(
            c.rules.iter().map(|r| r.id).collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
        assert_eq!(c.rules[2].action, Action::Allow);
    }

    #[test]
    fn modes_parse_and_reject() {
        assert_eq!(parse_mode("lockdown"), Ok(Mode::Lockdown));
        assert!(parse_mode("sideways").is_err());
    }
}
