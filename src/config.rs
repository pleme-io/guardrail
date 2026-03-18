use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::{env, fs};

use anyhow::Context;

use crate::model::{Category, GuardrailConfig, Rule};

const DEFAULTS_YAML: &str = include_str!("../rules/defaults.yaml");

// ═══════════════════════════════════════════════════════════════════
// RuleProvider trait — composable, mockable rule sources
// ═══════════════════════════════════════════════════════════════════

/// A source of guardrail rules. Implement for custom rule backends
/// (embedded, filesystem, remote, in-memory for testing).
pub trait RuleProvider {
    /// Provider name (for logging/diagnostics).
    fn name(&self) -> &str;

    /// Load rules from this provider.
    ///
    /// # Errors
    ///
    /// Returns an error if rules can't be loaded or parsed.
    fn rules(&self) -> anyhow::Result<Vec<Rule>>;
}

// ═══════════════════════════════════════════════════════════════════
// Built-in providers
// ═══════════════════════════════════════════════════════════════════

/// Compiled-in default rules (embedded via include_str!).
pub struct DefaultsProvider;

impl RuleProvider for DefaultsProvider {
    fn name(&self) -> &str { "defaults" }

    fn rules(&self) -> anyhow::Result<Vec<Rule>> {
        Ok(serde_yaml::from_str(DEFAULTS_YAML)?)
    }
}

/// Loads rules from a `rules.d/` directory. Each `.yaml` file is a
/// rule suite that can be independently added or removed.
pub struct DirectoryProvider {
    pub dir: PathBuf,
}

impl RuleProvider for DirectoryProvider {
    fn name(&self) -> &str { "directory" }

    fn rules(&self) -> anyhow::Result<Vec<Rule>> {
        let mut rules = Vec::new();
        if !self.dir.is_dir() {
            return Ok(rules);
        }
        let mut paths: Vec<_> = fs::read_dir(&self.dir)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "yaml" || e == "yml"))
            .collect();
        paths.sort();
        for path in paths {
            let content = fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            let batch: Vec<Rule> = serde_yaml::from_str(&content)
                .with_context(|| format!("parsing {}", path.display()))?;
            rules.extend(batch);
        }
        Ok(rules)
    }
}

/// In-memory rule provider for testing.
pub struct MockProvider {
    pub label: String,
    pub rules: Vec<Rule>,
}

impl RuleProvider for MockProvider {
    fn name(&self) -> &str { &self.label }

    fn rules(&self) -> anyhow::Result<Vec<Rule>> {
        Ok(self.rules.clone())
    }
}

// ═══════════════════════════════════════════════════════════════════
// Rule resolution — merges providers + config
// ═══════════════════════════════════════════════════════════════════

/// Collect rules from all providers, then apply config filters.
///
/// # Errors
///
/// Returns an error if any provider fails.
pub fn resolve(
    providers: &[&dyn RuleProvider],
    config: &GuardrailConfig,
) -> anyhow::Result<Vec<Rule>> {
    let mut all_rules = Vec::new();
    for provider in providers {
        let rules = provider.rules()
            .with_context(|| format!("loading rules from provider '{}'", provider.name()))?;
        all_rules.extend(rules);
    }

    // Append extra rules from user config
    all_rules.extend(config.extra_rules.clone());

    // Apply filters: category toggles + disabled rules
    let filtered: Vec<Rule> = all_rules
        .into_iter()
        .filter(|r| *config.categories.get(&r.category).unwrap_or(&true))
        .filter(|r| !config.disabled_rules.contains(&r.name))
        .collect();

    Ok(filtered)
}

// ═══════════════════════════════════════════════════════════════════
// Convenience functions
// ═══════════════════════════════════════════════════════════════════

/// Load compiled-in default rules.
pub fn default_rules() -> Vec<Rule> {
    DefaultsProvider.rules().expect("compiled-in defaults.yaml must be valid")
}

/// Shikumi config path: `~/.config/guardrail/guardrail.yaml`
#[must_use]
pub fn config_path() -> PathBuf {
    config_dir().join("guardrail.yaml")
}

/// Shikumi config directory: `~/.config/guardrail/`
#[must_use]
pub fn config_dir() -> PathBuf {
    env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env::var("HOME").unwrap_or_default()).join(".config"))
        .join("guardrail")
}

/// Rules.d directory: `~/.config/guardrail/rules.d/`
#[must_use]
pub fn rules_dir() -> PathBuf {
    config_dir().join("rules.d")
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

/// Legacy convenience: merge defaults + user config.
#[must_use]
pub fn resolve_rules(defaults: &[Rule], config: &GuardrailConfig) -> Vec<Rule> {
    let provider = MockProvider { label: "defaults".into(), rules: defaults.to_vec() };
    resolve(&[&provider], config).expect("mock provider cannot fail")
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;
    use tempfile::TempDir;

    fn test_rule(name: &str, category: Category) -> Rule {
        Rule {
            name: name.into(),
            pattern: name.into(),
            severity: Severity::Block,
            message: format!("{name} rule"),
            category,
        }
    }

    // ─── DefaultsProvider ────────────────────────────────────────

    #[test]
    fn defaults_parse() {
        let rules = DefaultsProvider.rules().unwrap();
        assert!(rules.len() >= 25, "expected 25+ default rules, got {}", rules.len());
    }

    #[test]
    fn defaults_have_all_categories() {
        let rules = DefaultsProvider.rules().unwrap();
        let cats: std::collections::BTreeSet<Category> =
            rules.iter().map(|r| r.category).collect();
        for cat in [
            Category::Filesystem, Category::Git, Category::Database,
            Category::Kubernetes, Category::Nix, Category::Docker,
            Category::Secrets, Category::Terraform, Category::Flux,
        ] {
            assert!(cats.contains(&cat), "missing category: {cat:?}");
        }
    }

    // ─── DirectoryProvider ───────────────────────────────────────

    #[test]
    fn directory_provider_loads_yaml() {
        let dir = TempDir::new().unwrap();
        let yaml = serde_yaml::to_string(&vec![
            test_rule("custom-fs", Category::Filesystem),
        ]).unwrap();
        fs::write(dir.path().join("custom.yaml"), &yaml).unwrap();

        let provider = DirectoryProvider { dir: dir.path().to_path_buf() };
        let rules = provider.rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "custom-fs");
    }

    #[test]
    fn directory_provider_loads_multiple_files() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("a.yaml"),
            serde_yaml::to_string(&vec![test_rule("rule-a", Category::Git)]).unwrap()
        ).unwrap();
        fs::write(dir.path().join("b.yaml"),
            serde_yaml::to_string(&vec![test_rule("rule-b", Category::Docker)]).unwrap()
        ).unwrap();

        let provider = DirectoryProvider { dir: dir.path().to_path_buf() };
        let rules = provider.rules().unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn directory_provider_deterministic_order() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("z.yaml"),
            serde_yaml::to_string(&vec![test_rule("z-rule", Category::Git)]).unwrap()
        ).unwrap();
        fs::write(dir.path().join("a.yaml"),
            serde_yaml::to_string(&vec![test_rule("a-rule", Category::Git)]).unwrap()
        ).unwrap();

        let provider = DirectoryProvider { dir: dir.path().to_path_buf() };
        let rules = provider.rules().unwrap();
        assert_eq!(rules[0].name, "a-rule"); // sorted by filename
        assert_eq!(rules[1].name, "z-rule");
    }

    #[test]
    fn directory_provider_empty_dir() {
        let dir = TempDir::new().unwrap();
        let provider = DirectoryProvider { dir: dir.path().to_path_buf() };
        assert!(provider.rules().unwrap().is_empty());
    }

    #[test]
    fn directory_provider_missing_dir() {
        let provider = DirectoryProvider { dir: PathBuf::from("/nonexistent") };
        assert!(provider.rules().unwrap().is_empty());
    }

    // ─── MockProvider ────────────────────────────────────────────

    #[test]
    fn mock_provider() {
        let provider = MockProvider {
            label: "test".into(),
            rules: vec![test_rule("mock", Category::Filesystem)],
        };
        assert_eq!(provider.name(), "test");
        assert_eq!(provider.rules().unwrap().len(), 1);
    }

    // ─── resolve() ───────────────────────────────────────────────

    #[test]
    fn resolve_merges_multiple_providers() {
        let p1 = MockProvider {
            label: "a".into(),
            rules: vec![test_rule("rule-a", Category::Filesystem)],
        };
        let p2 = MockProvider {
            label: "b".into(),
            rules: vec![test_rule("rule-b", Category::Git)],
        };
        let config = GuardrailConfig::default();
        let rules = resolve(&[&p1, &p2], &config).unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn resolve_applies_category_toggle() {
        let p = MockProvider {
            label: "test".into(),
            rules: vec![
                test_rule("fs-rule", Category::Filesystem),
                test_rule("git-rule", Category::Git),
            ],
        };
        let mut cats = BTreeMap::new();
        cats.insert(Category::Git, false);
        let config = GuardrailConfig { categories: cats, ..Default::default() };
        let rules = resolve(&[&p], &config).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "fs-rule");
    }

    #[test]
    fn resolve_applies_disabled_rules() {
        let p = MockProvider {
            label: "test".into(),
            rules: vec![
                test_rule("keep", Category::Filesystem),
                test_rule("drop", Category::Filesystem),
            ],
        };
        let config = GuardrailConfig {
            disabled_rules: vec!["drop".into()],
            ..Default::default()
        };
        let rules = resolve(&[&p], &config).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "keep");
    }

    #[test]
    fn resolve_appends_extra_rules() {
        let p = MockProvider { label: "test".into(), rules: vec![] };
        let config = GuardrailConfig {
            extra_rules: vec![test_rule("extra", Category::Secrets)],
            ..Default::default()
        };
        let rules = resolve(&[&p], &config).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "extra");
    }

    #[test]
    fn resolve_extra_rules_respect_category_toggle() {
        let p = MockProvider { label: "test".into(), rules: vec![] };
        let mut cats = BTreeMap::new();
        cats.insert(Category::Secrets, false);
        let config = GuardrailConfig {
            categories: cats,
            extra_rules: vec![test_rule("extra-secret", Category::Secrets)],
            ..Default::default()
        };
        let rules = resolve(&[&p], &config).unwrap();
        assert!(rules.is_empty());
    }

    // ─── Legacy convenience ──────────────────────────────────────

    #[test]
    fn resolve_rules_legacy() {
        let defaults = default_rules();
        let config = GuardrailConfig {
            disabled_rules: vec!["rm-rf-root".into()],
            ..Default::default()
        };
        let rules = resolve_rules(&defaults, &config);
        assert!(!rules.iter().any(|r| r.name == "rm-rf-root"));
    }

    #[test]
    fn empty_config_returns_all_defaults() {
        let defaults = default_rules();
        let config = GuardrailConfig::default();
        let rules = resolve_rules(&defaults, &config);
        assert_eq!(rules.len(), defaults.len());
    }

    // ─── Suite file loading ──────────────────────────────────────

    #[test]
    fn akeyless_suite_parses() {
        let yaml = include_str!("../rules/akeyless.yaml");
        let rules: Vec<Rule> = serde_yaml::from_str(yaml).unwrap();
        assert!(rules.len() >= 30, "expected 30+ akeyless rules, got {}", rules.len());
        assert!(rules.iter().all(|r| r.category == Category::Akeyless));
    }

    #[test]
    fn aws_suite_parses() {
        let yaml = include_str!("../rules/aws.yaml");
        let rules: Vec<Rule> = serde_yaml::from_str(yaml).unwrap();
        assert!(rules.len() >= 20, "expected 20+ aws rules, got {}", rules.len());
        assert!(rules.iter().all(|r| r.category == Category::Cloud));
    }

    #[test]
    fn gcp_suite_parses() {
        let yaml = include_str!("../rules/gcp.yaml");
        let rules: Vec<Rule> = serde_yaml::from_str(yaml).unwrap();
        assert!(rules.len() >= 10);
    }

    #[test]
    fn azure_suite_parses() {
        let yaml = include_str!("../rules/azure.yaml");
        let rules: Vec<Rule> = serde_yaml::from_str(yaml).unwrap();
        assert!(rules.len() >= 15);
    }

    #[test]
    fn process_suite_parses() {
        let yaml = include_str!("../rules/process.yaml");
        let rules: Vec<Rule> = serde_yaml::from_str(yaml).unwrap();
        assert!(rules.len() >= 5);
        assert!(rules.iter().all(|r| r.category == Category::Process));
    }

    #[test]
    fn network_suite_parses() {
        let yaml = include_str!("../rules/network.yaml");
        let rules: Vec<Rule> = serde_yaml::from_str(yaml).unwrap();
        assert!(rules.len() >= 5);
        assert!(rules.iter().all(|r| r.category == Category::Network));
    }

    #[test]
    fn nosql_suite_parses() {
        let yaml = include_str!("../rules/nosql.yaml");
        let rules: Vec<Rule> = serde_yaml::from_str(yaml).unwrap();
        assert!(rules.len() >= 5);
        assert!(rules.iter().all(|r| r.category == Category::Nosql));
    }

    #[test]
    fn sql_suite_parses() {
        let yaml = include_str!("../rules/sql.yaml");
        let rules: Vec<Rule> = serde_yaml::from_str(yaml).unwrap();
        assert!(rules.len() >= 35, "expected 35+ sql rules, got {}", rules.len());
        assert!(rules.iter().all(|r| r.category == Category::Database));
    }

    #[test]
    fn all_suites_have_unique_rule_names() {
        let mut all_names = std::collections::BTreeSet::new();
        let mut dupes = vec![];
        for yaml_str in [
            include_str!("../rules/defaults.yaml"),
            include_str!("../rules/akeyless.yaml"),
            include_str!("../rules/aws.yaml"),
            include_str!("../rules/gcp.yaml"),
            include_str!("../rules/azure.yaml"),
            include_str!("../rules/process.yaml"),
            include_str!("../rules/network.yaml"),
            include_str!("../rules/nosql.yaml"),
            include_str!("../rules/sql.yaml"),
        ] {
            let rules: Vec<Rule> = serde_yaml::from_str(yaml_str).unwrap();
            for rule in rules {
                if !all_names.insert(rule.name.clone()) {
                    dupes.push(rule.name);
                }
            }
        }
        assert!(dupes.is_empty(), "duplicate rule names across suites: {dupes:?}");
    }
}
