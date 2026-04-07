use regex::Regex;
use std::time::Instant;

use crate::engine::{PrefixPrefilter, Prefilter, RegexEngine, RuleEngine};
use crate::model::{Decision, Rule};

// ═══════════════════════════════════════════════════════════════════
// Auto-derivation: generate test commands from patterns
// ═══════════════════════════════════════════════════════════════════

/// Derive a command that MUST match the rule's regex pattern.
/// Uses explicit `test_block` if present, otherwise auto-derives from pattern.
#[must_use]
pub fn derive_test_block(rule: &Rule) -> String {
    if let Some(ref tb) = rule.test_block {
        return tb.clone();
    }
    synthesize_matching_command(&rule.pattern, &rule.name)
}

/// Derive a command that must NOT match the rule's regex pattern.
/// Uses explicit `test_allow` if present, otherwise auto-derives.
#[must_use]
pub fn derive_test_allow(rule: &Rule) -> String {
    if let Some(ref ta) = rule.test_allow {
        return ta.clone();
    }
    // Generic safe command — "cargo build" doesn't match any guardrail pattern
    "cargo build --release".to_owned()
}

/// Transform a regex pattern into a realistic CLI command that matches it.
///
/// Strategy: strip regex syntax, resolve alternations to concrete values,
/// replace character classes with minimal matches. Then verify the result
/// actually matches the pattern — if not, fall back to name-based derivation.
fn synthesize_matching_command(pattern: &str, name: &str) -> String {
    let re = Regex::new(pattern).ok();

    // Try multiple strategies, return the first that matches
    let candidates = [
        synthesize_from_pattern(pattern),
        synthesize_from_name(name),
    ];

    if let Some(re) = &re {
        for candidate in &candidates {
            if re.is_match(candidate) {
                return candidate.clone();
            }
        }
    }

    // Last resort: return pattern-derived even if unverified
    candidates.into_iter().next().unwrap_or_else(|| name.replace('-', " "))
}

/// Primary strategy: strip regex syntax to extract a literal command.
fn synthesize_from_pattern(pattern: &str) -> String {
    let mut s = pattern.to_owned();

    // 1. Strip anchors and flags
    s = s.replace("(?i)", "");
    s = s.replace("(?:^|\\s)", " ");
    s = s.replace("(?:^| )", " ");
    s = s.replace('^', "");
    s = s.replace('$', "");

    // 2. Resolve specific alternation groups (longer patterns first)
    let alternations: &[(&str, &str)] = &[
        ("(TABLE\\s+)?", "TABLE "),
        ("(TABLE )?", "TABLE "),
        ("(QUERY\\s+)?", ""),
        ("(-r\\s+)?", "-r "),
        ("-f?\\s*", "-f "),
        ("-f?", "-f"),
        ("(ROLE|USER)", "ROLE"),
        ("(sd|nvme|disk|vd)", "sda"),
        ("(akeyless|aky)", "akeyless"),
        ("(main|master)", "main"),
        ("(prod|production)", "production"),
        ("(server|db)", "server"),
        ("(account|container)", "account"),
        ("(-d|--decrypt)", "-d"),
        ("(-l|--limit)", "-l"),
        ("(python|django-admin)", "python"),
        ("(rails|rake)", "rails"),
        ("(rm\\s+-r|rb)", "rb"),
        ("(rm -r|rb)", "rb"),
        ("(mongosh?|mongo)", "mongosh"),
        ("(redis-cli|FLUSHALL)", "redis-cli FLUSHALL"),
        ("(ns|namespace)", "namespace"),
        ("(claim|composite)", "claim"),
        ("(cache-cluster|replication-group)", "cache-cluster"),
        ("(instances|databases)", "instances"),
        ("(dropDatabase|drop_database)", "dropDatabase"),
        ("(shutdown|poweroff|halt|reboot)", "shutdown"),
        ("(sshd|networking|docker|k3s|kubelet)", "docker"),
        ("(unload|bootout)", "unload"),
        ("(~|\\$HOME)", "~"),
        ("(GITHUB_TOKEN|AWS_SECRET|DATABASE_URL|API_KEY|PRIVATE_KEY)", "GITHUB_TOKEN"),
    ];
    for &(from, to) in alternations {
        s = s.replace(from, to);
    }

    // 3. Replace character classes
    let char_classes: &[(&str, &str)] = &[
        ("[a-zA-Z]*", ""),
        ("[a-zA-Z-]*", ""),
        ("[a-z-]*", ""),
        ("[a-z]*", ""),
        ("[;'\"\\)\\s]*", ""),
        ("[;'\")] *", ""),
        ("[;'\"\\)]*", ""),
    ];
    for &(from, to) in char_classes {
        s = s.replace(from, to);
    }

    // 4. Replace regex escapes
    let escapes: &[(&str, &str)] = &[
        ("\\s+", " "),
        ("\\s*", ""),
        ("\\s", " "),
        ("\\b", ""),
        ("\\-", "-"),
        ("\\.", "."),
        ("\\(", "("),
        ("\\)", ")"),
        ("\\*", "*"),
        ("\\|", "|"),
        ("\\w+", "test"),
        ("\\w", "x"),
        ("\\S+", "origin"),
        ("\\d+", "123"),
    ];
    for &(from, to) in escapes {
        s = s.replace(from, to);
    }

    // 5. Replace wildcards — minimal content
    s = s.replace(".*", " ");
    s = s.replace(".+", "value");

    // 6. Collapse multiple spaces
    while s.contains("  ") {
        s = s.replace("  ", " ");
    }

    s.trim().to_owned()
}

/// Fallback strategy: derive from rule name.
/// "aws-ec2-terminate" → "aws ec2 terminate --id test-123"
fn synthesize_from_name(name: &str) -> String {
    let cmd = name.replace('-', " ");
    format!("{cmd} --id test-123")
}

/// Wrap a command to ensure it passes the engine's fast-reject prefilter.
/// If the prefilter would skip DFA for this command, wraps in `echo '...'`
/// (echo is in the dangerous prefix set, so it always reaches the DFA).
fn ensure_engine_passthrough(cmd: &str) -> String {
    let prefilter = PrefixPrefilter;
    if prefilter.is_safe(cmd) {
        // Command would be fast-rejected — wrap to bypass prefilter
        format!("echo '{cmd}'")
    } else {
        cmd.to_owned()
    }
}

// ═══════════════════════════════════════════════════════════════════
// Validation functions
// ═══════════════════════════════════════════════════════════════════

/// Validate every rule at the regex level:
/// 1. Pattern compiles
/// 2. Auto-derived `test_block` matches the pattern
/// 3. Auto-derived `test_allow` does NOT match the pattern
#[must_use]
pub fn validate_all_rules_regex(rules: &[Rule]) -> Vec<String> {
    let mut failures = Vec::new();

    for rule in rules {
        // Compile pattern
        let re = match Regex::new(&rule.pattern) {
            Ok(r) => r,
            Err(e) => {
                failures.push(format!(
                    "rule '{}': pattern compile error: {e}",
                    rule.name
                ));
                continue;
            }
        };

        // test_block must match
        let test_block = derive_test_block(rule);
        if !re.is_match(&test_block) {
            failures.push(format!(
                "rule '{}': test_block '{}' did not match pattern '{}'",
                rule.name, test_block, rule.pattern
            ));
        }

        // test_allow must NOT match
        let test_allow = derive_test_allow(rule);
        if re.is_match(&test_allow) {
            failures.push(format!(
                "rule '{}': test_allow '{}' unexpectedly matched pattern '{}'",
                rule.name, test_allow, rule.pattern
            ));
        }
    }

    failures
}

/// Validate rules through the full engine pipeline:
/// 1. All rules compile into a `RegexSet`
/// 2. `test_block` commands produce Block or Warn (not Allow)
#[must_use]
pub fn validate_all_rules_engine(rules: &[Rule]) -> Vec<String> {
    let mut failures = Vec::new();

    let engine = match RegexEngine::new(rules.to_vec()) {
        Ok(e) => e,
        Err(e) => {
            failures.push(format!("RegexSet compilation failed: {e}"));
            return failures;
        }
    };

    for rule in rules {
        let test_block = derive_test_block(rule);
        let engine_cmd = ensure_engine_passthrough(&test_block);
        let decision = engine.check(&engine_cmd);

        if matches!(decision, Decision::Allow) {
            failures.push(format!(
                "rule '{}': command '{}' was ALLOWED by engine (expected Block/Warn)",
                rule.name, engine_cmd
            ));
        }
    }

    failures
}

// ═══════════════════════════════════════════════════════════════════
// Performance benchmarks
// ═══════════════════════════════════════════════════════════════════

/// Performance benchmark results.
pub struct BenchmarkResult {
    pub rule_count: usize,
    pub compile_time: std::time::Duration,
    pub total_match_time: std::time::Duration,
    pub avg_match_time: std::time::Duration,
    pub max_match_time: std::time::Duration,
    pub max_match_rule: String,
}

/// Benchmark `RegexSet` compilation and per-rule matching.
///
/// # Panics
///
/// Panics if the rules fail to compile into a `RegexSet`, which
/// indicates invalid regex patterns in the input.
#[must_use]
pub fn benchmark_rules(rules: &[Rule]) -> BenchmarkResult {
    let start = Instant::now();
    let engine = RegexEngine::new(rules.to_vec()).expect("rules must compile for benchmark");
    let compile_time = start.elapsed();

    let mut match_times = Vec::with_capacity(rules.len());
    let mut max_time = std::time::Duration::ZERO;
    let mut max_rule = String::new();

    for rule in rules {
        let test_block = derive_test_block(rule);
        let engine_cmd = ensure_engine_passthrough(&test_block);
        let start = Instant::now();
        let _ = engine.check(&engine_cmd);
        let elapsed = start.elapsed();
        match_times.push(elapsed);
        if elapsed > max_time {
            max_time = elapsed;
            max_rule.clone_from(&rule.name);
        }
    }

    let total_match: std::time::Duration = match_times.iter().sum();
    let count = u32::try_from(match_times.len().max(1)).unwrap_or(u32::MAX);

    BenchmarkResult {
        rule_count: rules.len(),
        compile_time,
        total_match_time: total_match,
        avg_match_time: total_match / count,
        max_match_time: max_time,
        max_match_rule: max_rule,
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::model::Rule;

    /// Load ALL rules from all embedded suites.
    fn all_suite_rules() -> Vec<Rule> {
        let suites: &[(&str, &str)] = &[
            ("defaults", include_str!("../rules/defaults.yaml")),
            ("akeyless", include_str!("../rules/akeyless.yaml")),
            ("akeyless-generated", include_str!("../rules/akeyless-generated.yaml")),
            ("aws", include_str!("../rules/aws.yaml")),
            ("aws-generated", include_str!("../rules/aws-generated.yaml")),
            ("azure", include_str!("../rules/azure.yaml")),
            ("gcp", include_str!("../rules/gcp.yaml")),
            ("network", include_str!("../rules/network.yaml")),
            ("nosql", include_str!("../rules/nosql.yaml")),
            ("process", include_str!("../rules/process.yaml")),
            ("sql", include_str!("../rules/sql.yaml")),
        ];

        let mut all = Vec::new();
        for &(name, yaml) in suites {
            let rules: Vec<Rule> = serde_yaml::from_str(yaml)
                .unwrap_or_else(|e| panic!("suite '{name}' failed to parse: {e}"));
            all.extend(rules);
        }
        all
    }

    // ── Regex-level validation ───────────────────────────────────

    #[test]
    fn all_default_rules_regex_valid() {
        let rules = config::default_rules();
        let failures = validate_all_rules_regex(&rules);
        if !failures.is_empty() {
            for f in &failures {
                eprintln!("  FAIL: {f}");
            }
            panic!(
                "{}/{} default rules failed regex validation",
                failures.len(),
                rules.len()
            );
        }
    }

    #[test]
    fn all_suite_rules_regex_valid() {
        let rules = all_suite_rules();
        let failures = validate_all_rules_regex(&rules);
        if !failures.is_empty() {
            for f in &failures {
                eprintln!("  FAIL: {f}");
            }
            panic!(
                "{}/{} suite rules failed regex validation",
                failures.len(),
                rules.len()
            );
        }
    }

    // ── Engine-level validation ──────────────────────────────────

    #[test]
    fn all_default_rules_engine_valid() {
        let rules = config::default_rules();
        let failures = validate_all_rules_engine(&rules);
        if !failures.is_empty() {
            for f in &failures {
                eprintln!("  FAIL: {f}");
            }
            panic!(
                "{}/{} default rules failed engine validation",
                failures.len(),
                rules.len()
            );
        }
    }

    #[test]
    fn all_suite_rules_engine_valid() {
        let rules = all_suite_rules();
        let failures = validate_all_rules_engine(&rules);
        if !failures.is_empty() {
            for f in &failures {
                eprintln!("  FAIL: {f}");
            }
            panic!(
                "{}/{} suite rules failed engine validation",
                failures.len(),
                rules.len()
            );
        }
    }

    // ── Compilation ──────────────────────────────────────────────

    #[test]
    fn all_suite_rules_compile_into_regexset() {
        let rules = all_suite_rules();
        let engine = RegexEngine::new(rules.clone());
        assert!(
            engine.is_ok(),
            "Failed to compile {} rules into RegexSet",
            rules.len()
        );
    }

    // ── Performance benchmarks ───────────────────────────────────

    #[test]
    fn performance_default_rules() {
        let rules = config::default_rules();
        let result = benchmark_rules(&rules);
        eprintln!(
            "Default rules ({} rules): compile={:?}, total_match={:?}, avg={:?}, max={:?} ({})",
            result.rule_count,
            result.compile_time,
            result.total_match_time,
            result.avg_match_time,
            result.max_match_time,
            result.max_match_rule,
        );
        // Sanity: compilation should be under 1s
        assert!(
            result.compile_time.as_secs() < 1,
            "Default rules compilation too slow: {:?}",
            result.compile_time
        );
    }

    #[test]
    fn performance_all_rules() {
        let rules = all_suite_rules();
        let result = benchmark_rules(&rules);
        eprintln!(
            "All rules ({} rules): compile={:?}, total_match={:?}, avg={:?}, max={:?} ({})",
            result.rule_count,
            result.compile_time,
            result.total_match_time,
            result.avg_match_time,
            result.max_match_time,
            result.max_match_rule,
        );
        // Sanity: compilation should be under 30s for ~2500 rules
        assert!(
            result.compile_time.as_secs() < 30,
            "All rules compilation too slow: {:?}",
            result.compile_time
        );
        // Average match should be under 50ms (DFA scan of 2500+ patterns)
        assert!(
            result.avg_match_time.as_millis() < 50,
            "Average match too slow: {:?}",
            result.avg_match_time
        );
    }

    // ── Synthesizer unit tests ───────────────────────────────────

    #[test]
    fn synthesize_simple_prefix_pattern() {
        let cmd = synthesize_from_pattern("(?i)akeyless\\s+delete\\-item\\b");
        assert_eq!(cmd, "akeyless delete-item");
    }

    #[test]
    fn synthesize_aws_pattern() {
        let cmd = synthesize_from_pattern("(?i)aws\\s+delete\\-analyzer\\b");
        assert_eq!(cmd, "aws delete-analyzer");
    }

    #[test]
    fn synthesize_rm_rf_root() {
        let cmd = synthesize_from_pattern("rm\\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\\s+/\\s*$");
        let re = Regex::new("rm\\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\\s+/\\s*$").unwrap();
        assert!(re.is_match(&cmd), "synthesized '{cmd}' doesn't match rm-rf-root");
    }

    #[test]
    fn synthesize_git_force_push_main() {
        let cmd = synthesize_from_pattern(
            "git\\s+push\\s+.*--force[a-z-]*\\s+\\S+\\s+(main|master)\\b",
        );
        let re = Regex::new("git\\s+push\\s+.*--force[a-z-]*\\s+\\S+\\s+(main|master)\\b")
            .unwrap();
        assert!(
            re.is_match(&cmd),
            "synthesized '{cmd}' doesn't match git-force-push-main"
        );
    }

    #[test]
    fn synthesize_sql_drop_table() {
        let cmd = synthesize_from_pattern("(?i)\\bDROP\\s+TABLE\\b");
        let re = Regex::new("(?i)\\bDROP\\s+TABLE\\b").unwrap();
        assert!(
            re.is_match(&cmd),
            "synthesized '{cmd}' doesn't match sql-drop-table"
        );
    }

    #[test]
    fn synthesize_sops_decrypt_pipe() {
        let cmd = synthesize_from_pattern("sops\\s+(-d|--decrypt)\\s+.*\\|");
        let re = Regex::new("sops\\s+(-d|--decrypt)\\s+.*\\|").unwrap();
        assert!(
            re.is_match(&cmd),
            "synthesized '{cmd}' doesn't match sops-decrypt-pipe"
        );
    }

    #[test]
    fn synthesize_mongo_drop_database() {
        let cmd = synthesize_from_pattern("(?i)db\\.(dropDatabase|drop_database)\\(\\)");
        let re = Regex::new("(?i)db\\.(dropDatabase|drop_database)\\(\\)").unwrap();
        assert!(
            re.is_match(&cmd),
            "synthesized '{cmd}' doesn't match mongo-drop-database"
        );
    }

    #[test]
    fn test_allow_never_matches_safe() {
        // The default test_allow should not match any rule
        let re_patterns = [
            "(?i)akeyless\\s+delete\\-item\\b",
            "(?i)\\bDROP\\s+TABLE\\b",
            "rm\\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\\s+/\\s*$",
            "git\\s+push\\s+--force",
            "terraform\\s+destroy",
        ];
        let safe = "cargo build --release";
        for pat in &re_patterns {
            let re = Regex::new(pat).unwrap();
            assert!(
                !re.is_match(safe),
                "test_allow '{safe}' matched pattern '{pat}'"
            );
        }
    }

    #[test]
    fn engine_passthrough_wraps_safe_commands() {
        let cmd = ensure_engine_passthrough("db.dropDatabase()");
        assert!(
            cmd.starts_with("echo "),
            "expected echo wrapper, got: {cmd}"
        );
    }

    #[test]
    fn engine_passthrough_preserves_dangerous() {
        let cmd = ensure_engine_passthrough("aws delete-bucket --bucket x");
        assert_eq!(cmd, "aws delete-bucket --bucket x");
    }

    #[test]
    fn engine_passthrough_preserves_sql_keywords() {
        let cmd = ensure_engine_passthrough("DROP TABLE users");
        assert_eq!(cmd, "DROP TABLE users");
    }

    #[test]
    fn prefilter_trait_used_correctly() {
        let p = PrefixPrefilter;
        // Safe command → prefilter says safe → would need wrapping
        assert!(p.is_safe("cat README.md"));
        // Dangerous command → prefilter says not safe → no wrapping needed
        assert!(!p.is_safe("rm -rf /"));
    }

    // ── Content scanning performance ────────────────────────────

    #[test]
    fn content_scan_performance() {
        use crate::hook;
        use std::time::Instant;

        // Simulate a large file write (1000 lines, mostly safe)
        let mut content = String::new();
        for i in 0..995 {
            content.push_str(&format!("const x{i} = {i};\n"));
        }
        // Add a few dangerous lines
        content.push_str("rm -rf /tmp\n");
        content.push_str("DROP TABLE users;\n");
        content.push_str("terraform destroy\n");
        content.push_str("echo safe\n");
        content.push_str("kubectl delete namespace prod\n");

        let start = Instant::now();
        let lines = hook::scan_content_lines(&content);
        let elapsed = start.elapsed();

        // Should find exactly the dangerous lines (prefilter rejects safe ones)
        assert!(lines.len() >= 4, "expected 4+ dangerous lines, got {}", lines.len());

        // Content scanning of 1000 lines should be under 100ms even in debug mode
        // (release mode: <1ms via prefilter fast-reject of safe lines)
        assert!(
            elapsed.as_millis() < 100,
            "Content scan too slow for 1000 lines: {elapsed:?}"
        );
        eprintln!("Content scan (1000 lines, {} dangerous): {elapsed:?}", lines.len());
    }

    // ── derive_test_block / derive_test_allow ────────────────────

    #[test]
    fn derive_test_block_uses_explicit_when_present() {
        let rule = Rule::builder("r", "pattern")
            .test_block("explicit block cmd")
            .build();
        assert_eq!(derive_test_block(&rule), "explicit block cmd");
    }

    #[test]
    fn derive_test_block_synthesizes_when_absent() {
        let rule = Rule::builder("r", r"rm\s+-rf").build();
        let cmd = derive_test_block(&rule);
        assert!(!cmd.is_empty(), "synthesized command should not be empty");
    }

    #[test]
    fn derive_test_allow_uses_explicit_when_present() {
        let rule = Rule::builder("r", "pattern")
            .test_allow("explicit allow cmd")
            .build();
        assert_eq!(derive_test_allow(&rule), "explicit allow cmd");
    }

    #[test]
    fn derive_test_allow_returns_default_when_absent() {
        let rule = Rule::builder("r", "pattern").build();
        assert_eq!(derive_test_allow(&rule), "cargo build --release");
    }

    // ── validate_all_rules_regex error branches ──────────────────

    #[test]
    fn validate_regex_reports_invalid_pattern() {
        let rules = vec![Rule::builder("bad-regex", "[invalid").build()];
        let failures = validate_all_rules_regex(&rules);
        assert!(!failures.is_empty());
        assert!(failures[0].contains("pattern compile error"));
    }

    #[test]
    fn validate_regex_reports_non_matching_test_block() {
        let rule = Rule::builder("mismatch", r"^zzz_never_match$")
            .test_block("this will not match")
            .build();
        let failures = validate_all_rules_regex(&[rule]);
        assert!(!failures.is_empty());
        assert!(failures[0].contains("did not match pattern"));
    }

    #[test]
    fn validate_regex_reports_matching_test_allow() {
        let rule = Rule::builder("false-positive", r"cargo")
            .test_block("cargo test")
            .test_allow("cargo build --release")
            .build();
        let failures = validate_all_rules_regex(&[rule]);
        assert!(!failures.is_empty());
        assert!(failures[0].contains("unexpectedly matched"));
    }

    #[test]
    fn validate_regex_empty_rules_no_failures() {
        let failures = validate_all_rules_regex(&[]);
        assert!(failures.is_empty());
    }

    // ── validate_all_rules_engine error branches ─────────────────

    #[test]
    fn validate_engine_reports_compilation_failure() {
        let rules = vec![Rule::builder("bad", "[invalid").build()];
        let failures = validate_all_rules_engine(&rules);
        assert!(!failures.is_empty());
        assert!(failures[0].contains("compilation failed"));
    }

    #[test]
    fn validate_engine_empty_rules_no_failures() {
        let failures = validate_all_rules_engine(&[]);
        assert!(failures.is_empty());
    }

    // ── benchmark_rules edge cases ──────────────────────────────

    #[test]
    fn benchmark_single_rule() {
        let rules = vec![
            Rule::builder("test-bench", r"rm\s+-rf")
                .test_block("rm -rf /")
                .build(),
        ];
        let result = benchmark_rules(&rules);
        assert_eq!(result.rule_count, 1);
        assert!(!result.max_match_rule.is_empty());
    }

    #[test]
    fn benchmark_result_fields_consistent() {
        let rules = config::default_rules();
        let result = benchmark_rules(&rules);
        assert_eq!(result.rule_count, rules.len());
        assert!(result.avg_match_time <= result.total_match_time);
        assert!(result.max_match_time <= result.total_match_time);
    }

    // ── synthesize_from_name ─────────────────────────────────────

    #[test]
    fn synthesize_from_name_basic() {
        let cmd = synthesize_from_name("aws-ec2-terminate");
        assert_eq!(cmd, "aws ec2 terminate --id test-123");
    }

    #[test]
    fn synthesize_from_name_single_word() {
        let cmd = synthesize_from_name("shutdown");
        assert_eq!(cmd, "shutdown --id test-123");
    }
}
