use std::path::{Path, PathBuf};
use std::{env, fs};

use anyhow::Context;

use crate::model::{GuardrailConfig, Rule};

const DEFAULTS_YAML: &str = include_str!("../rules/defaults.yaml");

/// Load compiled-in default rules.
pub fn default_rules() -> Vec<Rule> {
    serde_yaml::from_str(DEFAULTS_YAML).expect("compiled-in defaults.yaml must be valid")
}

/// Shikumi config path: `~/.config/guardrail/guardrail.yaml`
#[must_use]
pub fn config_path() -> PathBuf {
    env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env::var("HOME").unwrap_or_default()).join(".config"))
        .join("guardrail/guardrail.yaml")
}

/// Load user config from disk. Returns default if file doesn't exist.
///
/// # Errors
///
/// Returns an error if the file exists but can't be parsed.
pub fn load_user_config(path: &Path) -> anyhow::Result<GuardrailConfig> {
    if !path.exists() {
        return Ok(GuardrailConfig::default());
    }
    let content = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    serde_yaml::from_str(&content)
        .with_context(|| format!("parsing {}", path.display()))
}

/// Merge defaults + user config into final active rule set.
#[must_use]
pub fn resolve_rules(defaults: &[Rule], config: &GuardrailConfig) -> Vec<Rule> {
    let mut rules: Vec<Rule> = defaults
        .iter()
        // Filter by category toggles
        .filter(|r| *config.categories.get(&r.category).unwrap_or(&true))
        // Filter out disabled rules
        .filter(|r| !config.disabled_rules.contains(&r.name))
        .cloned()
        .collect();

    // Append extra rules (also filtered by category)
    for rule in &config.extra_rules {
        if *config.categories.get(&rule.category).unwrap_or(&true) {
            rules.push(rule.clone());
        }
    }

    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Category, Severity};

    #[test]
    fn defaults_parse() {
        let rules = default_rules();
        assert!(rules.len() >= 25, "expected 25+ default rules, got {}", rules.len());
    }

    #[test]
    fn defaults_have_all_categories() {
        let rules = default_rules();
        let categories: std::collections::BTreeSet<Category> =
            rules.iter().map(|r| r.category).collect();
        assert!(categories.contains(&Category::Filesystem));
        assert!(categories.contains(&Category::Git));
        assert!(categories.contains(&Category::Database));
        assert!(categories.contains(&Category::Kubernetes));
        assert!(categories.contains(&Category::Nix));
        assert!(categories.contains(&Category::Docker));
        assert!(categories.contains(&Category::Secrets));
    }

    #[test]
    fn resolve_disables_rule() {
        let defaults = default_rules();
        let config = GuardrailConfig {
            disabled_rules: vec!["rm-rf-root".into()],
            ..Default::default()
        };
        let rules = resolve_rules(&defaults, &config);
        assert!(!rules.iter().any(|r| r.name == "rm-rf-root"));
    }

    #[test]
    fn resolve_disables_category() {
        let defaults = default_rules();
        let mut categories = std::collections::BTreeMap::new();
        categories.insert(Category::Docker, false);
        let config = GuardrailConfig { categories, ..Default::default() };
        let rules = resolve_rules(&defaults, &config);
        assert!(!rules.iter().any(|r| r.category == Category::Docker));
    }

    #[test]
    fn resolve_adds_extra_rules() {
        let defaults = default_rules();
        let config = GuardrailConfig {
            extra_rules: vec![Rule {
                name: "custom-rule".into(),
                pattern: "dangerous-command".into(),
                severity: Severity::Block,
                message: "Custom block".into(),
                category: Category::Filesystem,
            }],
            ..Default::default()
        };
        let rules = resolve_rules(&defaults, &config);
        assert!(rules.iter().any(|r| r.name == "custom-rule"));
    }

    #[test]
    fn empty_config_returns_all_defaults() {
        let defaults = default_rules();
        let config = GuardrailConfig::default();
        let rules = resolve_rules(&defaults, &config);
        assert_eq!(rules.len(), defaults.len());
    }
}
