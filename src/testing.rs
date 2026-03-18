use crate::config;
use crate::engine::{RegexEngine, RuleEngine};
use crate::model::{Decision, Rule};

/// Validate that every rule's regex pattern actually compiles and
/// matches at least one plausible command derived from its name.
///
/// This is a smoke test — it verifies that no rule has a broken
/// regex and that the pattern is not vacuously unmatchable.
pub fn validate_all_rules(rules: &[Rule]) -> Vec<String> {
    let mut failures = Vec::new();

    // First: verify all rules compile into a RegexSet
    let engine = match RegexEngine::new(rules.to_vec()) {
        Ok(e) => e,
        Err(e) => {
            failures.push(format!("RegexSet compilation failed: {e}"));
            return failures;
        }
    };

    // For each rule, generate a synthetic command from the pattern
    // and verify it matches
    for rule in rules {
        let test_cmd = synthesize_command(&rule.pattern, &rule.name);
        let decision = engine.check(&test_cmd);

        match decision {
            Decision::Allow => {
                failures.push(format!(
                    "rule '{}' did not match its own synthesized command: '{}'",
                    rule.name, test_cmd
                ));
            }
            _ => {} // Block or Warn — good
        }
    }

    failures
}

/// Generate a plausible command from a rule name.
/// Rule names follow the convention: {provider}-{operation}
/// e.g., "aws-ec2-terminate-instances" → "aws ec2 terminate-instances"
/// e.g., "sql-drop-table" → "psql -c 'DROP TABLE test'"
/// e.g., "akeyless-delete-item" → "akeyless delete-item"
fn synthesize_command(pattern: &str, name: &str) -> String {
    // Try to extract a literal from the regex pattern
    // Strip regex syntax to find the core command
    let cleaned = pattern
        .replace("(?i)", "")
        .replace("\\s+", " ")
        .replace("\\s", " ")
        .replace("\\b", "")
        .replace("\\.", ".")
        .replace("\\-", "-")
        .replace("\\(", "(")
        .replace("\\)", ")")
        .replace("\\*", "*")
        .replace("\\|", "|")
        .replace("(?:^|\\s)", " ")
        .replace("(?:^| )", " ")
        .replace("[a-zA-Z]*", "")
        .replace("[a-zA-Z-]*", "")
        .replace("[a-z-]*", "")
        .replace("\\S+", "origin")
        .replace("\\w+", "test")
        .replace("\\d+", "123")
        .replace("\\w", "x")
        .replace(".*", " --flag value")
        .replace(".+", "value")
        .replace("(TABLE )?", "TABLE ")
        .replace("(TABLE\\s+)?", "TABLE ")
        .replace("(ns|namespace)", "namespace")
        .replace("(ROLE|USER)", "ROLE")
        .replace("(sd|nvme|disk|vd)", "sda")
        .replace("(akeyless|aky)", "akeyless")
        .replace("(main|master)", "main")
        .replace("(prod|production)", "production")
        .replace("(server|db)", "server")
        .replace("(account|container)", "account")
        .replace("(-d|--decrypt)", "-d")
        .replace("(python|django-admin)", "python")
        .replace("(rails|rake)", "rails")
        .replace("(rm -r|rb)", "rb")
        .replace("(mongosh?|mongo)", "mongo")
        .replace("(redis-cli|FLUSHALL)", "redis-cli FLUSHALL")
        .replace("$", "")
        .replace("^", "")
        .replace("[;'\")] *", ";")
        .replace("[;'\"\\)\\s]*", ";")
        .trim()
        .to_owned();

    if cleaned.is_empty() {
        // Fallback: derive from name
        name.replace('-', " ")
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_default_rules_match_synthesized_commands() {
        let rules = config::default_rules();
        let failures = validate_all_rules(&rules);
        if !failures.is_empty() {
            for f in &failures {
                eprintln!("  FAIL: {f}");
            }
            panic!("{} default rules failed validation", failures.len());
        }
    }

    #[test]
    fn all_suite_rules_compile() {
        // Verify every suite file's rules compile into valid regexes
        for (name, yaml) in [
            ("akeyless", include_str!("../rules/akeyless.yaml")),
            ("aws", include_str!("../rules/aws.yaml")),
            ("aws-generated", include_str!("../rules/aws-generated.yaml")),
            ("akeyless-generated", include_str!("../rules/akeyless-generated.yaml")),
            ("azure", include_str!("../rules/azure.yaml")),
            ("gcp", include_str!("../rules/gcp.yaml")),
            ("network", include_str!("../rules/network.yaml")),
            ("nosql", include_str!("../rules/nosql.yaml")),
            ("process", include_str!("../rules/process.yaml")),
            ("sql", include_str!("../rules/sql.yaml")),
        ] {
            let rules: Vec<Rule> = serde_yaml::from_str(yaml)
                .unwrap_or_else(|e| panic!("suite '{name}' failed to parse: {e}"));
            let engine = RegexEngine::new(rules.clone());
            assert!(engine.is_ok(), "suite '{name}' failed to compile RegexSet");
        }
    }

    #[test]
    fn all_suite_rules_match_synthesized_commands() {
        let mut total = 0;
        let mut failed = 0;

        for (name, yaml) in [
            ("akeyless", include_str!("../rules/akeyless.yaml")),
            ("aws", include_str!("../rules/aws.yaml")),
            ("azure", include_str!("../rules/azure.yaml")),
            ("gcp", include_str!("../rules/gcp.yaml")),
            ("network", include_str!("../rules/network.yaml")),
            ("nosql", include_str!("../rules/nosql.yaml")),
            ("process", include_str!("../rules/process.yaml")),
            ("sql", include_str!("../rules/sql.yaml")),
        ] {
            let rules: Vec<Rule> = serde_yaml::from_str(yaml).unwrap();
            let failures = validate_all_rules(&rules);
            total += rules.len();
            failed += failures.len();
            if !failures.is_empty() {
                eprintln!("Suite '{name}': {} failures:", failures.len());
                for f in &failures {
                    eprintln!("  {f}");
                }
            }
        }

        // Allow up to 10% failure rate for synthesized commands
        // (some regex patterns are too complex for naive synthesis)
        let threshold = total / 10;
        assert!(
            failed <= threshold,
            "{failed}/{total} rules failed synthesis matching (threshold: {threshold})"
        );
    }
}
