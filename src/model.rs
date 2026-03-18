use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub pattern: String,
    pub severity: Severity,
    pub message: String,
    pub category: Category,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Block { rule: String, message: String },
    Warn { rule: String, message: String },
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
