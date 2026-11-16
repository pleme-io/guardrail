//! What the command lexer knows about shells, wrappers and remote shells, as
//! data: the shipped table is `rules/lexicon.yaml`, and guardrail.yaml's
//! `lexicon` key extends it per machine.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

const SHIPPED_YAML: &str = include_str!("../rules/lexicon.yaml");

/// A word that precedes the real command (`sudo`, `env`, `timeout 5`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Wrapper {
    pub name: String,
    #[serde(default)]
    pub value_flags: Vec<String>,
    #[serde(default)]
    pub positionals: usize,
}

/// A command that runs the rest of its line on another host or machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RemoteShell {
    pub command: Vec<String>,
    #[serde(default)]
    pub value_flags: Vec<String>,
    #[serde(default = "one")]
    pub positionals: usize,
}

const fn one() -> usize {
    1
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Lexicon {
    pub shells: Vec<String>,
    pub wrappers: Vec<Wrapper>,
    pub remote_shells: Vec<RemoteShell>,
}

/// guardrail.yaml `lexicon`: entries added to the shipped table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LexiconOverrides {
    #[serde(default)]
    pub extra_shells: Vec<String>,
    #[serde(default)]
    pub extra_wrappers: Vec<Wrapper>,
    #[serde(default)]
    pub extra_remote_shells: Vec<RemoteShell>,
}

impl Lexicon {
    /// The table compiled in from `rules/lexicon.yaml`.
    ///
    /// # Panics
    ///
    /// Only if the compiled-in file does not parse, which a unit test rules out.
    #[must_use]
    pub fn shipped() -> &'static Self {
        static SHIPPED: OnceLock<Lexicon> = OnceLock::new();
        SHIPPED.get_or_init(|| {
            serde_norway::from_str(SHIPPED_YAML).expect("rules/lexicon.yaml is valid")
        })
    }

    #[must_use]
    pub fn configured(overrides: &LexiconOverrides) -> Self {
        let mut lexicon = Self::shipped().clone();
        lexicon
            .shells
            .extend(overrides.extra_shells.iter().cloned());
        lexicon
            .wrappers
            .extend(overrides.extra_wrappers.iter().cloned());
        lexicon
            .remote_shells
            .extend(overrides.extra_remote_shells.iter().cloned());
        lexicon
    }

    #[must_use]
    pub fn from_user_config() -> Self {
        let overrides = crate::config::load_user_config(&crate::config::config_path())
            .map(|c| c.lexicon)
            .unwrap_or_default();
        Self::configured(&overrides)
    }

    #[must_use]
    pub fn is_shell(&self, name: &str) -> bool {
        self.shells.iter().any(|s| s == name)
    }

    #[must_use]
    pub fn wrapper(&self, name: &str) -> Option<&Wrapper> {
        self.wrappers.iter().find(|w| w.name == name)
    }

    /// The remote shell `name rest…` invokes, and the words after its command.
    #[must_use]
    pub fn remote_shell<'a>(
        &self,
        name: &str,
        rest: &'a [String],
    ) -> Option<(&RemoteShell, &'a [String])> {
        self.remote_shells.iter().find_map(|r| {
            let (first, tail) = r.command.split_first()?;
            (first == name
                && rest.len() >= tail.len()
                && rest.iter().zip(tail).all(|(w, t)| w == t))
            .then(|| (r, &rest[tail.len()..]))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_table_parses_and_holds_ssh() {
        let l = Lexicon::shipped();
        assert!(l.is_shell("bash"));
        assert!(l.wrapper("sudo").is_some());
        let rest: Vec<String> = vec!["rio".into(), "reboot".into()];
        assert!(l.remote_shell("ssh", &rest).is_some());
    }

    #[test]
    fn tailscale_ssh_is_a_remote_shell_and_tailscale_status_is_not() {
        let l = Lexicon::shipped();
        let ssh: Vec<String> = vec!["ssh".into(), "rio".into()];
        let (_, after) = l.remote_shell("tailscale", &ssh).unwrap();
        assert_eq!(after, ["rio".to_owned()]);
        let status: Vec<String> = vec!["status".into()];
        assert!(l.remote_shell("tailscale", &status).is_none());
    }

    #[test]
    fn overrides_extend_the_shipped_table() {
        let o: LexiconOverrides = serde_norway::from_str(
            "extraRemoteShells: [{command: [kubectl, exec], valueFlags: [-n, -c]}]\nextraShells: [nu]",
        )
        .unwrap();
        let l = Lexicon::configured(&o);
        let rest: Vec<String> = vec!["exec".into(), "pod".into()];
        assert!(l.remote_shell("kubectl", &rest).is_some());
        assert!(l.is_shell("nu"));
        assert!(l.is_shell("bash"));
    }

    #[test]
    fn an_unknown_key_is_refused() {
        assert!(serde_norway::from_str::<LexiconOverrides>("extraShell: [nu]").is_err());
    }
}
