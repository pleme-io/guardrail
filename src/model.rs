use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Block,
    Warn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
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
