use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Severity {
    Block,
    Warn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Category {
    Filesystem,
    Git,
    Database,
    Kubernetes,
    Nix,
    Docker,
    Secrets,
    Terraform,
    Cloud,
    Flux,
    Akeyless,
    Process,
    Network,
    Nosql,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub pattern: String,
    pub severity: Severity,
    pub message: String,
    pub category: Category,
    /// Command that MUST match this rule (for testing).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_block: Option<String>,
    /// Command that must NOT match this rule (for testing).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_allow: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[must_use = "a Decision should be inspected, not discarded"]
pub enum Decision {
    Allow,
    Block { rule: String, message: String },
    Warn { rule: String, message: String },
}

// ── Display implementations ─────────────────────────────────────

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Block => f.write_str("block"),
            Self::Warn => f.write_str("warn"),
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Filesystem => "filesystem",
            Self::Git => "git",
            Self::Database => "database",
            Self::Kubernetes => "kubernetes",
            Self::Nix => "nix",
            Self::Docker => "docker",
            Self::Secrets => "secrets",
            Self::Terraform => "terraform",
            Self::Cloud => "cloud",
            Self::Flux => "flux",
            Self::Akeyless => "akeyless",
            Self::Process => "process",
            Self::Network => "network",
            Self::Nosql => "nosql",
        };
        f.write_str(s)
    }
}

impl FromStr for Severity {
    type Err = ParseEnumError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "block" => Ok(Self::Block),
            "warn" => Ok(Self::Warn),
            _ => Err(ParseEnumError {
                type_name: "Severity",
                value: s.to_owned(),
            }),
        }
    }
}

impl FromStr for Category {
    type Err = ParseEnumError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "filesystem" => Ok(Self::Filesystem),
            "git" => Ok(Self::Git),
            "database" => Ok(Self::Database),
            "kubernetes" => Ok(Self::Kubernetes),
            "nix" => Ok(Self::Nix),
            "docker" => Ok(Self::Docker),
            "secrets" => Ok(Self::Secrets),
            "terraform" => Ok(Self::Terraform),
            "cloud" => Ok(Self::Cloud),
            "flux" => Ok(Self::Flux),
            "akeyless" => Ok(Self::Akeyless),
            "process" => Ok(Self::Process),
            "network" => Ok(Self::Network),
            "nosql" => Ok(Self::Nosql),
            _ => Err(ParseEnumError {
                type_name: "Category",
                value: s.to_owned(),
            }),
        }
    }
}

/// Error returned when parsing a string into a `Severity` or `Category` fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseEnumError {
    pub type_name: &'static str,
    pub value: String,
}

impl fmt::Display for ParseEnumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown {} value: '{}'", self.type_name, self.value)
    }
}

impl std::error::Error for ParseEnumError {}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => f.write_str("allow"),
            Self::Block { rule, message } => write!(f, "block [{rule}]: {message}"),
            Self::Warn { rule, message } => write!(f, "warn [{rule}]: {message}"),
        }
    }
}

// ── Builder ─────────────────────────────────────────────────────

/// Fluent builder for constructing `Rule` values (primarily for tests).
pub struct RuleBuilder {
    name: String,
    pattern: String,
    severity: Severity,
    message: String,
    category: Category,
    test_block: Option<String>,
    test_allow: Option<String>,
}

impl RuleBuilder {
    #[must_use]
    pub fn severity(mut self, s: Severity) -> Self {
        self.severity = s;
        self
    }
    #[must_use]
    pub fn message(mut self, m: impl Into<String>) -> Self {
        self.message = m.into();
        self
    }
    #[must_use]
    pub fn category(mut self, c: Category) -> Self {
        self.category = c;
        self
    }
    #[must_use]
    pub fn test_block(mut self, t: impl Into<String>) -> Self {
        self.test_block = Some(t.into());
        self
    }
    #[must_use]
    pub fn test_allow(mut self, t: impl Into<String>) -> Self {
        self.test_allow = Some(t.into());
        self
    }
    #[must_use]
    pub fn build(self) -> Rule {
        Rule {
            name: self.name,
            pattern: self.pattern,
            severity: self.severity,
            message: self.message,
            category: self.category,
            test_block: self.test_block,
            test_allow: self.test_allow,
        }
    }
}

impl Rule {
    /// Create a builder with name and pattern. Defaults: Block, Filesystem, empty message.
    #[must_use]
    pub fn builder(name: impl Into<String>, pattern: impl Into<String>) -> RuleBuilder {
        RuleBuilder {
            name: name.into(),
            pattern: pattern.into(),
            severity: Severity::Block,
            message: String::new(),
            category: Category::Filesystem,
            test_block: None,
            test_allow: None,
        }
    }
}

/// User config file (shikumi convention: ~/.config/guardrail/guardrail.yaml).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardrailConfig {
    /// Toggle entire categories. Missing = enabled.
    #[serde(default)]
    pub categories: BTreeMap<Category, bool>,
    /// Additional rules merged with compiled-in defaults.
    #[serde(default)]
    pub extra_rules: Vec<Rule>,
    /// Compiled-in rule names to disable.
    #[serde(default)]
    pub disabled_rules: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Severity ────────────────────────────────────────────────

    #[test]
    fn severity_display_all_variants() {
        assert_eq!(Severity::Block.to_string(), "block");
        assert_eq!(Severity::Warn.to_string(), "warn");
    }

    #[test]
    fn severity_serde_round_trip() {
        let json = serde_json::to_string(&Severity::Block).unwrap();
        assert_eq!(json, r#""block""#);
        let back: Severity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Severity::Block);

        let json = serde_json::to_string(&Severity::Warn).unwrap();
        assert_eq!(json, r#""warn""#);
        let back: Severity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Severity::Warn);
    }

    #[test]
    fn severity_yaml_round_trip() {
        let yaml = serde_yaml::to_string(&Severity::Block).unwrap();
        let back: Severity = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(back, Severity::Block);
    }

    #[test]
    fn severity_invalid_deserialize() {
        let result: Result<Severity, _> = serde_json::from_str(r#""invalid""#);
        assert!(result.is_err(), "invalid severity should fail to deserialize");
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Block < Severity::Warn);
    }

    #[test]
    fn severity_fromstr_round_trip() {
        for sev in [Severity::Block, Severity::Warn] {
            let s = sev.to_string();
            let parsed: Severity = s.parse().unwrap();
            assert_eq!(parsed, sev);
        }
    }

    #[test]
    fn severity_fromstr_invalid() {
        let err = "invalid".parse::<Severity>().unwrap_err();
        assert_eq!(err.type_name, "Severity");
        assert_eq!(err.value, "invalid");
        assert!(err.to_string().contains("Severity"));
    }

    // ── Category ────────────────────────────────────────────────

    #[test]
    fn category_display_all_variants() {
        let expected = [
            (Category::Filesystem, "filesystem"),
            (Category::Git, "git"),
            (Category::Database, "database"),
            (Category::Kubernetes, "kubernetes"),
            (Category::Nix, "nix"),
            (Category::Docker, "docker"),
            (Category::Secrets, "secrets"),
            (Category::Terraform, "terraform"),
            (Category::Cloud, "cloud"),
            (Category::Flux, "flux"),
            (Category::Akeyless, "akeyless"),
            (Category::Process, "process"),
            (Category::Network, "network"),
            (Category::Nosql, "nosql"),
        ];
        for (cat, name) in expected {
            assert_eq!(cat.to_string(), name, "Display mismatch for {cat:?}");
        }
    }

    #[test]
    fn category_serde_round_trip_all_variants() {
        let all = [
            Category::Filesystem, Category::Git, Category::Database,
            Category::Kubernetes, Category::Nix, Category::Docker,
            Category::Secrets, Category::Terraform, Category::Cloud,
            Category::Flux, Category::Akeyless, Category::Process,
            Category::Network, Category::Nosql,
        ];
        for cat in all {
            let json = serde_json::to_string(&cat).unwrap();
            let back: Category = serde_json::from_str(&json).unwrap();
            assert_eq!(back, cat, "serde round-trip failed for {cat:?}");
        }
    }

    #[test]
    fn category_invalid_deserialize() {
        let result: Result<Category, _> = serde_json::from_str(r#""bogus""#);
        assert!(result.is_err());
    }

    #[test]
    fn category_ordering() {
        assert!(Category::Filesystem < Category::Git);
        assert!(Category::Network < Category::Nosql);
    }

    #[test]
    fn category_fromstr_round_trip() {
        let all = [
            Category::Filesystem, Category::Git, Category::Database,
            Category::Kubernetes, Category::Nix, Category::Docker,
            Category::Secrets, Category::Terraform, Category::Cloud,
            Category::Flux, Category::Akeyless, Category::Process,
            Category::Network, Category::Nosql,
        ];
        for cat in all {
            let s = cat.to_string();
            let parsed: Category = s.parse().unwrap();
            assert_eq!(parsed, cat, "FromStr round-trip failed for {cat:?}");
        }
    }

    #[test]
    fn category_fromstr_invalid() {
        let err = "bogus".parse::<Category>().unwrap_err();
        assert_eq!(err.type_name, "Category");
        assert!(err.to_string().contains("bogus"));
    }

    // ── Decision ────────────────────────────────────────────────

    #[test]
    fn decision_display_all_variants() {
        assert_eq!(Decision::Allow.to_string(), "allow");
        assert_eq!(
            Decision::Block { rule: "r".into(), message: "m".into() }.to_string(),
            "block [r]: m"
        );
        assert_eq!(
            Decision::Warn { rule: "r".into(), message: "m".into() }.to_string(),
            "warn [r]: m"
        );
    }

    #[test]
    fn decision_equality() {
        assert_eq!(Decision::Allow, Decision::Allow);
        assert_ne!(Decision::Allow, Decision::Block { rule: "r".into(), message: "m".into() });
        assert_ne!(
            Decision::Block { rule: "a".into(), message: "m".into() },
            Decision::Block { rule: "b".into(), message: "m".into() },
        );
    }

    #[test]
    fn decision_debug() {
        let d = Decision::Block { rule: "test".into(), message: "msg".into() };
        let debug = format!("{d:?}");
        assert!(debug.contains("Block"));
        assert!(debug.contains("test"));
    }

    #[test]
    fn decision_clone() {
        let d = Decision::Warn { rule: "r".into(), message: "m".into() };
        let cloned = d.clone();
        assert_eq!(d, cloned);
    }

    // ── Rule ────────────────────────────────────────────────────

    #[test]
    fn rule_serde_json_round_trip() {
        let rule = Rule::builder("test-rule", r"rm\s+-rf")
            .severity(Severity::Block)
            .message("danger")
            .category(Category::Filesystem)
            .test_block("rm -rf /")
            .test_allow("rm file.txt")
            .build();

        let json = serde_json::to_string(&rule).unwrap();
        let back: Rule = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "test-rule");
        assert_eq!(back.pattern, r"rm\s+-rf");
        assert_eq!(back.severity, Severity::Block);
        assert_eq!(back.message, "danger");
        assert_eq!(back.category, Category::Filesystem);
        assert_eq!(back.test_block.as_deref(), Some("rm -rf /"));
        assert_eq!(back.test_allow.as_deref(), Some("rm file.txt"));
    }

    #[test]
    fn rule_serde_yaml_round_trip() {
        let rule = Rule::builder("yaml-rule", "pattern")
            .severity(Severity::Warn)
            .message("warning")
            .category(Category::Git)
            .build();

        let yaml = serde_yaml::to_string(&rule).unwrap();
        let back: Rule = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(back.name, "yaml-rule");
        assert_eq!(back.severity, Severity::Warn);
        assert!(back.test_block.is_none());
        assert!(back.test_allow.is_none());
    }

    #[test]
    fn rule_optional_test_fields_skip_serializing() {
        let rule = Rule::builder("no-test", "pat").build();
        let json = serde_json::to_string(&rule).unwrap();
        assert!(!json.contains("test_block"), "test_block should be skipped when None");
        assert!(!json.contains("test_allow"), "test_allow should be skipped when None");
    }

    #[test]
    fn rule_deserialize_missing_optional_fields() {
        let json = r#"{"name":"min","pattern":"p","severity":"block","message":"m","category":"git"}"#;
        let rule: Rule = serde_json::from_str(json).unwrap();
        assert!(rule.test_block.is_none());
        assert!(rule.test_allow.is_none());
    }

    #[test]
    fn rule_equality() {
        let r1 = Rule::builder("a", "p").build();
        let r2 = Rule::builder("a", "p").build();
        assert_eq!(r1, r2);
    }

    // ── RuleBuilder ─────────────────────────────────────────────

    #[test]
    fn builder_defaults() {
        let rule = Rule::builder("name", "pattern").build();
        assert_eq!(rule.name, "name");
        assert_eq!(rule.pattern, "pattern");
        assert_eq!(rule.severity, Severity::Block);
        assert_eq!(rule.category, Category::Filesystem);
        assert!(rule.message.is_empty());
        assert!(rule.test_block.is_none());
        assert!(rule.test_allow.is_none());
    }

    #[test]
    fn builder_all_setters() {
        let rule = Rule::builder("n", "p")
            .severity(Severity::Warn)
            .message("msg")
            .category(Category::Docker)
            .test_block("block cmd")
            .test_allow("allow cmd")
            .build();
        assert_eq!(rule.severity, Severity::Warn);
        assert_eq!(rule.message, "msg");
        assert_eq!(rule.category, Category::Docker);
        assert_eq!(rule.test_block.as_deref(), Some("block cmd"));
        assert_eq!(rule.test_allow.as_deref(), Some("allow cmd"));
    }

    #[test]
    fn builder_accepts_string_types() {
        let name = String::from("owned-name");
        let pattern = String::from("owned-pattern");
        let rule = Rule::builder(name, pattern)
            .message(String::from("owned-message"))
            .test_block(String::from("owned-block"))
            .test_allow(String::from("owned-allow"))
            .build();
        assert_eq!(rule.name, "owned-name");
    }

    // ── GuardrailConfig ─────────────────────────────────────────

    #[test]
    fn config_default_is_empty() {
        let config = GuardrailConfig::default();
        assert!(config.categories.is_empty());
        assert!(config.extra_rules.is_empty());
        assert!(config.disabled_rules.is_empty());
    }

    #[test]
    fn config_serde_round_trip() {
        let mut config = GuardrailConfig::default();
        config.categories.insert(Category::Git, false);
        config.disabled_rules.push("rm-rf-root".into());
        config.extra_rules.push(Rule::builder("custom", "pat").build());

        let yaml = serde_yaml::to_string(&config).unwrap();
        let back: GuardrailConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(back.categories.get(&Category::Git), Some(&false));
        assert_eq!(back.disabled_rules, vec!["rm-rf-root"]);
        assert_eq!(back.extra_rules.len(), 1);
    }

    #[test]
    fn config_deserialize_empty_yaml() {
        let config: GuardrailConfig = serde_yaml::from_str("{}").unwrap();
        assert!(config.categories.is_empty());
        assert!(config.extra_rules.is_empty());
        assert!(config.disabled_rules.is_empty());
    }

    #[test]
    fn config_camel_case_field_names() {
        let yaml = r#"
disabledRules:
  - some-rule
extraRules: []
"#;
        let config: GuardrailConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.disabled_rules, vec!["some-rule"]);
    }

    #[test]
    fn rule_vec_serde_yaml() {
        let rules = vec![
            Rule::builder("r1", "p1").severity(Severity::Block).build(),
            Rule::builder("r2", "p2").severity(Severity::Warn).build(),
        ];
        let yaml = serde_yaml::to_string(&rules).unwrap();
        let back: Vec<Rule> = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].name, "r1");
        assert_eq!(back[1].name, "r2");
    }

    // ── Invalid YAML deserialization ─────────────────────────────

    #[test]
    fn rule_invalid_severity_yaml() {
        let yaml = r#"
- name: bad
  pattern: "x"
  severity: panic
  message: "nope"
  category: git
"#;
        let result: Result<Vec<Rule>, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err(), "invalid severity should fail deserialization");
    }

    #[test]
    fn rule_invalid_category_yaml() {
        let yaml = r#"
- name: bad
  pattern: "x"
  severity: block
  message: "nope"
  category: nonexistent
"#;
        let result: Result<Vec<Rule>, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err(), "invalid category should fail deserialization");
    }

    #[test]
    fn rule_missing_required_field_yaml() {
        let yaml = r#"
- name: incomplete
  severity: block
"#;
        let result: Result<Vec<Rule>, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err(), "missing required fields should fail");
    }

    #[test]
    fn config_invalid_category_key_yaml() {
        let yaml = r#"
categories:
  nonexistent: false
"#;
        let result: Result<GuardrailConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err(), "invalid category key should fail");
    }

    #[test]
    fn config_nested_invalid_extra_rule() {
        let yaml = r#"
extraRules:
  - name: bad
    pattern: "x"
    severity: invalid_severity
    message: "nope"
    category: git
"#;
        let result: Result<GuardrailConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err(), "invalid nested rule should fail");
    }
}
