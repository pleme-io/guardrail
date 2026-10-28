use regex::Regex;

use crate::model::{MatchMode, Rule};
use crate::shell;

/// One rule's pattern, compiled for its match mode.
#[derive(Debug, Clone)]
pub struct RuleMatcher {
    mode: MatchMode,
    pattern: Regex,
}

impl RuleMatcher {
    /// # Errors
    ///
    /// The rule's pattern is not a valid regex.
    pub fn new(rule: &Rule) -> Result<Self, regex::Error> {
        let pattern = match rule.mode {
            MatchMode::Text => Regex::new(&rule.pattern)?,
            MatchMode::Command => Regex::new(&format!("^(?:{})", rule.pattern))?,
        };
        Ok(Self {
            mode: rule.mode,
            pattern,
        })
    }

    #[must_use]
    pub fn is_match(&self, text: &str) -> bool {
        match self.mode {
            MatchMode::Text => self.pattern.is_match(text),
            MatchMode::Command => self.matches_any(&shell::commands(text)),
        }
    }

    /// Whether a command-mode pattern matches any of `commands`, lexed once by the caller.
    #[must_use]
    pub fn matches_any(&self, commands: &[String]) -> bool {
        commands.iter().any(|c| self.pattern.is_match(c))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shutdown() -> Rule {
        let rules: Vec<Rule> =
            serde_norway::from_str(include_str!("../../rules/process.yaml")).unwrap();
        rules.into_iter().find(|r| r.name == "shutdown").unwrap()
    }

    const RECEIPT: &str = r#"ssh rio 'journalctl -b -2 --no-pager | rg -i "eboot|poweroff|halt"'"#;

    #[test]
    fn command_mode_reads_the_command_not_its_arguments() {
        let m = RuleMatcher::new(&shutdown()).unwrap();
        assert!(!m.is_match(RECEIPT));
        assert!(m.is_match("ssh rio 'sudo reboot'"));
    }

    #[test]
    fn text_mode_restores_word_anywhere() {
        let mut rule = shutdown();
        rule.mode = MatchMode::Text;
        let m = RuleMatcher::new(&rule).unwrap();
        assert!(m.is_match(RECEIPT));
        assert!(m.is_match("ssh rio 'sudo reboot'"));
    }
}
