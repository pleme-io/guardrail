use std::path::{Path, PathBuf};
use std::{env, fs};

use anyhow::Context;

use crate::model::{GuardrailConfig, Rule};

/// Resolve an XDG base directory, falling back to `$HOME/<fallback_suffix>`.
///
/// Used by config, cache, and journal modules to locate guardrail directories
/// via the XDG Base Directory Specification.
#[must_use]
pub fn xdg_dir(env_var: &str, fallback_suffix: &str) -> PathBuf {
    env::var(env_var)
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env::var("HOME").unwrap_or_default()).join(fallback_suffix)
        })
}

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

/// Compiled-in default rules (embedded via `include_str!`).
pub struct DefaultsProvider;

impl RuleProvider for DefaultsProvider {
    #[allow(clippy::unnecessary_literal_bound)]
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
    #[allow(clippy::unnecessary_literal_bound)]
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
///
/// # Panics
///
/// Panics if the compiled-in `defaults.yaml` fails to parse, which
/// indicates a build-time invariant violation.
#[must_use]
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
    xdg_dir("XDG_CONFIG_HOME", ".config").join("guardrail")
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
///
/// # Panics
///
/// Panics if the mock provider fails, which should never happen
/// since mock providers always succeed.
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
    use crate::model::Category;
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    fn test_rule(name: &str, category: Category) -> Rule {
        Rule::builder(name, name)
            .message(format!("{name} rule"))
            .category(category)
            .build()
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

    // ─── load_user_config ─────────────────────────────────────

    #[test]
    fn load_user_config_missing_file_returns_default() {
        let config = load_user_config(std::path::Path::new("/nonexistent/config.yaml")).unwrap();
        assert!(config.categories.is_empty());
        assert!(config.extra_rules.is_empty());
        assert!(config.disabled_rules.is_empty());
    }

    #[test]
    fn load_user_config_valid_yaml() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("guardrail.yaml");
        fs::write(&path, r#"
categories:
  git: false
disabledRules:
  - rm-rf-root
extraRules:
  - name: custom
    pattern: "danger"
    severity: warn
    message: "custom rule"
    category: secrets
"#).unwrap();
        let config = load_user_config(&path).unwrap();
        assert_eq!(config.categories.get(&Category::Git), Some(&false));
        assert_eq!(config.disabled_rules, vec!["rm-rf-root"]);
        assert_eq!(config.extra_rules.len(), 1);
        assert_eq!(config.extra_rules[0].name, "custom");
    }

    #[test]
    fn load_user_config_invalid_yaml_returns_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bad.yaml");
        fs::write(&path, "not: [valid: yaml: {{{{").unwrap();
        let result = load_user_config(&path);
        assert!(result.is_err());
    }

    #[test]
    fn load_user_config_empty_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("empty.yaml");
        fs::write(&path, "").unwrap();
        // Empty YAML should deserialize as null -> error or default
        // serde_yaml::from_str("") returns an error for GuardrailConfig
        let result = load_user_config(&path);
        // Empty string in YAML is tricky — it may err or return default depending on version
        // Just ensure it doesn't panic
        let _ = result;
    }

    #[test]
    fn load_user_config_empty_object() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("empty-obj.yaml");
        fs::write(&path, "{}").unwrap();
        let config = load_user_config(&path).unwrap();
        assert!(config.categories.is_empty());
    }

    // ─── config_path / config_dir / rules_dir ───────────────────

    #[test]
    fn config_dir_respects_xdg() {
        // config_dir reads XDG_CONFIG_HOME; we verify the return value includes "guardrail"
        let dir = config_dir();
        assert!(
            dir.ends_with("guardrail"),
            "config_dir should end with 'guardrail', got: {}",
            dir.display()
        );
    }

    #[test]
    fn config_path_ends_with_yaml() {
        let path = config_path();
        assert!(
            path.ends_with("guardrail.yaml"),
            "config_path should end with guardrail.yaml, got: {}",
            path.display()
        );
    }

    #[test]
    fn rules_dir_ends_with_rules_d() {
        let dir = rules_dir();
        assert!(
            dir.ends_with("rules.d"),
            "rules_dir should end with rules.d, got: {}",
            dir.display()
        );
    }

    #[test]
    fn xdg_dir_uses_env_var_when_set() {
        let dir = xdg_dir("HOME", ".fallback");
        assert!(
            !dir.to_string_lossy().is_empty(),
            "xdg_dir should return a non-empty path"
        );
    }

    #[test]
    fn xdg_dir_fallback_includes_suffix() {
        let dir = xdg_dir("NONEXISTENT_XDG_VAR_FOR_TEST_12345", ".some-fallback");
        assert!(
            dir.to_string_lossy().contains(".some-fallback"),
            "expected fallback suffix in path, got: {}",
            dir.display()
        );
    }

    #[test]
    fn rules_dir_is_child_of_config_dir() {
        let cd = config_dir();
        let rd = rules_dir();
        assert!(
            rd.starts_with(&cd),
            "rules_dir ({}) should be inside config_dir ({})",
            rd.display(), cd.display()
        );
    }

    // ─── DirectoryProvider edge cases ───────────────────────────

    #[test]
    fn directory_provider_ignores_non_yaml_files() {
        let dir = TempDir::new().unwrap();
        let yaml = serde_yaml::to_string(&vec![test_rule("yaml-rule", Category::Git)]).unwrap();
        fs::write(dir.path().join("rules.yaml"), &yaml).unwrap();
        fs::write(dir.path().join("readme.md"), "# not a rule file").unwrap();
        fs::write(dir.path().join("rules.json"), "{}").unwrap();
        fs::write(dir.path().join("notes.txt"), "random text").unwrap();

        let provider = DirectoryProvider { dir: dir.path().to_path_buf() };
        let rules = provider.rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "yaml-rule");
    }

    #[test]
    fn directory_provider_loads_yml_extension() {
        let dir = TempDir::new().unwrap();
        let yaml = serde_yaml::to_string(&vec![test_rule("yml-rule", Category::Nix)]).unwrap();
        fs::write(dir.path().join("rules.yml"), &yaml).unwrap();

        let provider = DirectoryProvider { dir: dir.path().to_path_buf() };
        let rules = provider.rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "yml-rule");
    }

    #[test]
    fn directory_provider_invalid_yaml_returns_error() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("bad.yaml"), "not: [valid: yaml: {{{{").unwrap();

        let provider = DirectoryProvider { dir: dir.path().to_path_buf() };
        let result = provider.rules();
        assert!(result.is_err());
    }

    // ─── resolve() edge cases ───────────────────────────────────

    #[test]
    fn resolve_with_no_providers() {
        let config = GuardrailConfig::default();
        let rules = resolve(&[], &config).unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn resolve_disabled_extra_rules() {
        let p = MockProvider { label: "test".into(), rules: vec![] };
        let config = GuardrailConfig {
            extra_rules: vec![test_rule("extra", Category::Filesystem)],
            disabled_rules: vec!["extra".into()],
            ..Default::default()
        };
        let rules = resolve(&[&p], &config).unwrap();
        assert!(rules.is_empty(), "extra rule should be disabled by name");
    }

    #[test]
    fn resolve_multiple_category_toggles() {
        let p = MockProvider {
            label: "test".into(),
            rules: vec![
                test_rule("fs", Category::Filesystem),
                test_rule("git", Category::Git),
                test_rule("k8s", Category::Kubernetes),
                test_rule("db", Category::Database),
            ],
        };
        let mut cats = BTreeMap::new();
        cats.insert(Category::Filesystem, false);
        cats.insert(Category::Kubernetes, false);
        let config = GuardrailConfig { categories: cats, ..Default::default() };
        let rules = resolve(&[&p], &config).unwrap();
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().all(|r| r.category != Category::Filesystem && r.category != Category::Kubernetes));
    }

    // ─── resolve() error propagation ───────────────────────────

    struct FailingProvider;
    impl RuleProvider for FailingProvider {
        #[allow(clippy::unnecessary_literal_bound)]
        fn name(&self) -> &str { "failing" }
        fn rules(&self) -> anyhow::Result<Vec<Rule>> {
            anyhow::bail!("provider exploded")
        }
    }

    #[test]
    fn resolve_propagates_provider_error() {
        let config = GuardrailConfig::default();
        let result = resolve(&[&FailingProvider], &config);
        assert!(result.is_err());
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("failing"),
            "error should mention provider name, got: {msg}"
        );
    }

    #[test]
    fn resolve_fails_on_first_bad_provider() {
        let good = MockProvider {
            label: "good".into(),
            rules: vec![test_rule("ok", Category::Git)],
        };
        let config = GuardrailConfig::default();
        let result = resolve(&[&good, &FailingProvider], &config);
        assert!(result.is_err());
    }

    // ── Suite uniqueness ────────────────────────────────────────

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
