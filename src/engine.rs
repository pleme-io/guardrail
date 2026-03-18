use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;
use std::sync::LazyLock;

use regex::{RegexSet, RegexSetBuilder};

use crate::model::{Decision, Rule, Severity};

// ═══════════════════════════════════════════════════════════════════
// Trait: Normalizer — pluggable command preprocessing
// ═══════════════════════════════════════════════════════════════════

/// Abstracts command normalization (e.g. stripping nix store paths).
///
/// Uses `Cow` to avoid allocation when no transformation is needed.
/// Implementations must be `Send + Sync` for use in cached engines.
pub trait Normalizer: Send + Sync {
    fn normalize<'a>(&self, command: &'a str) -> Cow<'a, str>;
}

// ═══════════════════════════════════════════════════════════════════
// Trait: Prefilter — pluggable fast-reject
// ═══════════════════════════════════════════════════════════════════

/// Abstracts the fast-reject prefilter that skips DFA matching for
/// commands that are definitely safe.
///
/// Returns `true` if the command is safe (skip DFA). Returns `false`
/// if the command might be dangerous (must run DFA).
pub trait Prefilter: Send + Sync {
    fn is_safe(&self, command: &str) -> bool;
}

// ═══════════════════════════════════════════════════════════════════
// Trait: RuleEngine — pluggable matching
// ═══════════════════════════════════════════════════════════════════

/// Trait for testable, mockable rule matching.
pub trait RuleEngine {
    fn check(&self, command: &str) -> Decision;
    fn rules(&self) -> &[Rule];
    fn rule_count(&self) -> usize {
        self.rules().len()
    }
}

// ═══════════════════════════════════════════════════════════════════
// Normalizer implementations
// ═══════════════════════════════════════════════════════════════════

static NIX_PATH_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"/nix/store/[a-z0-9]+-[^/]+/bin/").unwrap()
});

/// Strips `/nix/store/{hash}-{pkg}/bin/` prefixes from commands.
/// Returns `Cow::Borrowed` when no nix path is present (zero alloc).
#[derive(Debug, Clone, Copy, Default)]
pub struct NixStoreNormalizer;

impl Normalizer for NixStoreNormalizer {
    fn normalize<'a>(&self, command: &'a str) -> Cow<'a, str> {
        if NIX_PATH_RE.is_match(command) {
            Cow::Owned(NIX_PATH_RE.replace_all(command, "").into_owned())
        } else {
            Cow::Borrowed(command)
        }
    }
}

/// No-op normalizer — returns commands unchanged.
/// Use in tests to isolate engine logic from normalization.
#[derive(Debug, Clone, Copy, Default)]
pub struct IdentityNormalizer;

impl Normalizer for IdentityNormalizer {
    fn normalize<'a>(&self, command: &'a str) -> Cow<'a, str> {
        Cow::Borrowed(command)
    }
}

// ═══════════════════════════════════════════════════════════════════
// Prefilter implementations
// ═══════════════════════════════════════════════════════════════════

/// First-word prefixes that COULD trigger a rule.
const DANGEROUS_PREFIXES: &[&str] = &[
    // filesystem
    "rm", "dd", "mkfs", "chmod",
    // git
    "git",
    // database / SQL
    "psql", "mysql", "sqlite3", "sqlcmd", "sqlx", "diesel", "prisma",
    "liquibase", "flyway", "knex", "rails", "rake", "python", "django-admin",
    "mongosh", "mongo",
    // kubernetes
    "kubectl", "helm", "flux",
    // cloud
    "aws", "gcloud", "gsutil", "az", "bq",
    // nix
    "nix", "nix-collect-garbage",
    // docker
    "docker",
    // secrets
    "sops", "echo",
    // terraform / iac
    "terraform", "pulumi", "ansible-playbook",
    // akeyless
    "akeyless", "aky",
    // process
    "kill", "killall", "pkill", "shutdown", "poweroff", "halt", "reboot",
    "systemctl", "launchctl",
    // network
    "iptables", "ufw", "ip", "nft",
    // nosql
    "redis-cli",
    // curl (for elasticsearch)
    "curl",
    // mysql admin
    "mysqladmin",
];

static PREFIX_SET: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    DANGEROUS_PREFIXES.iter().copied().collect()
});

/// Production prefilter: skips DFA for commands whose first 3 words
/// don't match a known dangerous prefix AND don't contain SQL keywords.
///
/// Safe commands (~99%): ~50ns. Dangerous commands: forwarded to DFA.
#[derive(Debug, Clone, Copy, Default)]
pub struct PrefixPrefilter;

impl PrefixPrefilter {
    /// Access the static set of dangerous prefixes (for test utilities).
    #[must_use]
    pub fn prefix_set() -> &'static HashSet<&'static str> {
        &PREFIX_SET
    }
}

impl Prefilter for PrefixPrefilter {
    fn is_safe(&self, command: &str) -> bool {
        // Zero-alloc prefix scan: iterate first 3 words without collecting to Vec
        let mut count = 0;
        for word in command.split_whitespace() {
            if count >= 3 {
                break;
            }
            if PREFIX_SET.contains(word) || PREFIX_SET.iter().any(|p| word.starts_with(p)) {
                return false;
            }
            count += 1;
        }
        // Zero-alloc SQL keyword scan: byte-level case-insensitive search
        // avoids the String allocation of command.to_uppercase()
        if contains_ascii_ci(command.as_bytes(), b"DROP ")
            || contains_ascii_ci(command.as_bytes(), b"TRUNCATE ")
            || contains_ascii_ci(command.as_bytes(), b"DELETE FROM")
            || contains_ascii_ci(command.as_bytes(), b"FLUSHALL")
            || contains_ascii_ci(command.as_bytes(), b"FLUSHDB")
        {
            return false;
        }
        true
    }
}

/// Case-insensitive ASCII substring search without allocation.
/// `needle` must be uppercase ASCII bytes.
#[inline]
fn contains_ascii_ci(haystack: &[u8], needle: &[u8]) -> bool {
    let n = needle.len();
    if n == 0 {
        return true;
    }
    if haystack.len() < n {
        return false;
    }
    haystack
        .windows(n)
        .any(|w| w.iter().zip(needle).all(|(a, b)| a.to_ascii_uppercase() == *b))
}

/// No-op prefilter — nothing is safe, all commands reach the DFA.
/// Use in tests to guarantee full pattern matching.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullPrefilter;

impl Prefilter for NullPrefilter {
    fn is_safe(&self, _command: &str) -> bool {
        false
    }
}

// ═══════════════════════════════════════════════════════════════════
// RegexEngine — generic over Normalizer + Prefilter
// ═══════════════════════════════════════════════════════════════════

/// Production rule engine: pluggable normalizer + prefilter + RegexSet DFA.
///
/// Default type parameters give zero-cost production behavior via
/// monomorphization. Tests can substitute `IdentityNormalizer` and/or
/// `NullPrefilter` for isolation.
///
/// # Examples
///
/// ```no_run
/// use guardrail::engine::*;
/// # fn main() -> anyhow::Result<()> {
/// let rules = vec![]; // load from config
/// // Production (default):
/// let engine = RegexEngine::new(rules.clone())?;
/// // Testing (no normalization, no prefilter):
/// let engine = RegexEngine::with_plugins(rules, IdentityNormalizer, NullPrefilter)?;
/// # Ok(())
/// # }
/// ```
pub struct RegexEngine<N: Normalizer = NixStoreNormalizer, P: Prefilter = PrefixPrefilter> {
    set: RegexSet,
    rules: Vec<Rule>,
    normalizer: N,
    prefilter: P,
}

impl<N: Normalizer + fmt::Debug, P: Prefilter + fmt::Debug> fmt::Debug for RegexEngine<N, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegexEngine")
            .field("rule_count", &self.rules.len())
            .field("normalizer", &self.normalizer)
            .field("prefilter", &self.prefilter)
            .finish()
    }
}

/// Default constructor — production configuration.
impl RegexEngine {
    /// Create an engine with `NixStoreNormalizer` + `PrefixPrefilter`.
    ///
    /// # Errors
    ///
    /// Returns an error if any regex pattern is invalid or the compiled
    /// DFA exceeds the 100MB size limit.
    pub fn new(rules: Vec<Rule>) -> anyhow::Result<Self> {
        Self::with_plugins(rules, NixStoreNormalizer, PrefixPrefilter)
    }
}

impl<N: Normalizer, P: Prefilter> RegexEngine<N, P> {
    /// Create an engine with custom normalizer and prefilter.
    ///
    /// # Errors
    ///
    /// Returns an error if any regex pattern is invalid.
    pub fn with_plugins(rules: Vec<Rule>, normalizer: N, prefilter: P) -> anyhow::Result<Self> {
        let patterns: Vec<&str> = rules.iter().map(|r| r.pattern.as_str()).collect();
        let set = RegexSetBuilder::new(&patterns)
            .size_limit(100 * 1024 * 1024) // 100MB for 2,500+ rules
            .build()
            .map_err(|e| anyhow::anyhow!("invalid regex in rule set: {e}"))?;
        Ok(Self {
            set,
            rules,
            normalizer,
            prefilter,
        })
    }
}

impl<N: Normalizer, P: Prefilter> RuleEngine for RegexEngine<N, P> {
    fn check(&self, command: &str) -> Decision {
        let normalized = self.normalizer.normalize(command);

        if self.prefilter.is_safe(&normalized) {
            return Decision::Allow;
        }

        let matches = self.set.matches(&normalized);
        if !matches.matched_any() {
            return Decision::Allow;
        }

        // Block takes priority — early-exit on first Block match.
        let mut best_warn: Option<&Rule> = None;

        for idx in matches.iter() {
            let rule = &self.rules[idx];
            match rule.severity {
                Severity::Block => {
                    return Decision::Block {
                        rule: rule.name.clone(),
                        message: rule.message.clone(),
                    };
                }
                Severity::Warn if best_warn.is_none() => best_warn = Some(rule),
                _ => {}
            }
        }

        if let Some(rule) = best_warn {
            return Decision::Warn {
                rule: rule.name.clone(),
                message: rule.message.clone(),
            };
        }

        Decision::Allow
    }

    fn rules(&self) -> &[Rule] {
        &self.rules
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::model::Category;

    fn engine() -> RegexEngine {
        RegexEngine::new(config::default_rules()).unwrap()
    }

    fn assert_blocks(cmd: &str) {
        let e = engine();
        match e.check(cmd) {
            Decision::Block { .. } => {}
            other => panic!("expected Block for '{cmd}', got {other}"),
        }
    }

    fn assert_warns(cmd: &str) {
        let e = engine();
        match e.check(cmd) {
            Decision::Warn { .. } => {}
            other => panic!("expected Warn for '{cmd}', got {other}"),
        }
    }

    fn assert_allows(cmd: &str) {
        let e = engine();
        match e.check(cmd) {
            Decision::Allow => {}
            other => panic!("expected Allow for '{cmd}', got {other}"),
        }
    }

    // ── Normalizer trait ─────────────────────────────────────────

    #[test]
    fn nix_normalizer_strips_store_path() {
        let n = NixStoreNormalizer;
        let result = n.normalize("/nix/store/abc123-pkg-1.0/bin/guardrail check");
        assert_eq!(&*result, "guardrail check");
        assert!(matches!(result, Cow::Owned(_)));
    }

    #[test]
    fn nix_normalizer_borrows_when_no_path() {
        let n = NixStoreNormalizer;
        let result = n.normalize("cargo test");
        assert_eq!(&*result, "cargo test");
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    #[test]
    fn nix_normalizer_strips_multiple_paths() {
        let n = NixStoreNormalizer;
        let result =
            n.normalize("/nix/store/abc-foo-1.0/bin/cmd1 && /nix/store/def-bar-2.0/bin/cmd2");
        assert_eq!(&*result, "cmd1 && cmd2");
    }

    #[test]
    fn identity_normalizer_is_noop() {
        let n = IdentityNormalizer;
        let result = n.normalize("anything");
        assert!(matches!(result, Cow::Borrowed("anything")));
    }

    // ── Prefilter trait ──────────────────────────────────────────

    #[test]
    fn prefix_prefilter_safe_commands() {
        let p = PrefixPrefilter;
        assert!(p.is_safe("ls -la"));
        assert!(p.is_safe("cargo test"));
        assert!(p.is_safe("cat file.txt"));
        assert!(p.is_safe("rg pattern ."));
    }

    #[test]
    fn prefix_prefilter_dangerous_commands() {
        let p = PrefixPrefilter;
        assert!(!p.is_safe("rm -rf /"));
        assert!(!p.is_safe("git push --force"));
        assert!(!p.is_safe("kubectl delete namespace prod"));
        assert!(!p.is_safe("terraform destroy"));
    }

    #[test]
    fn prefix_prefilter_sql_keywords() {
        let p = PrefixPrefilter;
        assert!(!p.is_safe("echo 'DROP TABLE users' | psql"));
    }

    #[test]
    fn null_prefilter_never_safe() {
        let p = NullPrefilter;
        assert!(!p.is_safe("ls -la"));
        assert!(!p.is_safe("cargo test"));
    }

    // ── Engine with plugins ──────────────────────────────────────

    #[test]
    fn engine_with_null_prefilter_checks_everything() {
        let rules = config::default_rules();
        let engine =
            RegexEngine::with_plugins(rules, NixStoreNormalizer, NullPrefilter).unwrap();
        // Even "safe" commands like "ls" reach the DFA — but no rule matches
        assert!(matches!(engine.check("ls -la"), Decision::Allow));
        // Dangerous commands still blocked
        assert!(matches!(engine.check("rm -rf /"), Decision::Block { .. }));
    }

    #[test]
    fn engine_with_identity_normalizer_no_nix_strip() {
        let rules = config::default_rules();
        let engine =
            RegexEngine::with_plugins(rules, IdentityNormalizer, PrefixPrefilter).unwrap();
        // Without normalization, nix store paths in the command would affect matching
        // (the "rm" would be in the store path, not as a standalone command)
        assert!(matches!(
            engine.check("/nix/store/abc123-coreutils-9.0/bin/rm -rf /"),
            Decision::Allow // identity normalizer doesn't strip the path
        ));
    }

    #[test]
    fn engine_debug_impl() {
        let engine = engine();
        let debug = format!("{engine:?}");
        assert!(debug.contains("RegexEngine"));
        assert!(debug.contains("rule_count"));
    }

    // ── Nix store path normalization ─────────────────────────────

    #[test]
    fn nix_shell_wrapped_mkfs_not_blocked() {
        let cmd = "/nix/store/abc123-e2fsprogs-1.47/bin/crate2nix generate";
        assert_allows(cmd);
    }

    #[test]
    fn actual_mkfs_still_blocked() {
        assert_blocks("mkfs.ext4 /dev/sda1");
        assert_blocks("sudo mkfs.ext4 /dev/sda1");
    }

    #[test]
    fn nix_store_path_with_real_danger() {
        assert_blocks("/nix/store/abc123-coreutils-9.0/bin/rm -rf /");
    }

    // ── Filesystem ──────────────────────────────────────────────

    #[test] fn rm_rf_root_blocked()        { assert_blocks("rm -rf /"); }
    #[test] fn rm_rf_root_var_blocked()    { assert_blocks("rm -rf /"); }
    #[test] fn rm_rf_home_blocked()        { assert_blocks("rm -rf ~"); }
    #[test] fn rm_rf_home_var_blocked()    { assert_blocks("rm -rf $HOME"); }
    #[test] fn rm_rf_cwd_blocked()         { assert_blocks("rm -rf ."); }
    #[test] fn rm_rf_target_allowed()      { assert_allows("rm -rf ./target"); }
    #[test] fn rm_rf_subdir_allowed()      { assert_allows("rm -rf ~/code/old-project"); }
    #[test] fn rm_single_file_allowed()    { assert_allows("rm file.txt"); }
    #[test] fn dd_disk_blocked()           { assert_blocks("dd if=/dev/zero of=/dev/sda bs=1M"); }
    #[test] fn dd_file_allowed()           { assert_allows("dd if=input.img of=output.img"); }
    #[test] fn mkfs_blocked()              { assert_blocks("mkfs.ext4 /dev/sda1"); }

    // ── Git ─────────────────────────────────────────────────────

    #[test] fn force_push_main_blocked()     { assert_blocks("git push --force origin main"); }
    #[test] fn force_push_master_blocked()   { assert_blocks("git push --force origin master"); }
    #[test] fn force_push_bare_blocked()     { assert_blocks("git push --force"); }
    #[test] fn force_push_feature_allowed()  { assert_allows("git push --force origin feature-xyz"); }
    #[test] fn normal_push_allowed()         { assert_allows("git push origin main"); }
    #[test] fn reset_hard_warned()           { assert_warns("git reset --hard HEAD~1"); }
    #[test] fn reset_soft_allowed()          { assert_allows("git reset --soft HEAD~1"); }
    #[test] fn clean_force_warned()          { assert_warns("git clean -fd"); }
    #[test] fn branch_force_delete_warned()  { assert_warns("git branch -D old-branch"); }
    #[test] fn branch_delete_allowed()       { assert_allows("git branch -d merged-branch"); }

    // ── Database ────────────────────────────────────────────────

    #[test] fn drop_table_blocked()            { assert_blocks("psql -c 'DROP TABLE users'"); }
    #[test] fn drop_table_lower_blocked()      { assert_blocks("psql -c 'drop table users'"); }
    #[test] fn drop_database_blocked()         { assert_blocks("psql -c 'DROP DATABASE mydb'"); }
    #[test] fn drop_schema_blocked()           { assert_blocks("mysql -e 'DROP SCHEMA test'"); }
    #[test] fn truncate_blocked()              { assert_blocks("psql -c 'TRUNCATE TABLE logs'"); }
    #[test] fn delete_no_where_blocked()       { assert_blocks("psql -c 'DELETE FROM users'"); }
    #[test] fn delete_with_where_allowed()     { assert_allows("psql -c 'DELETE FROM users WHERE id = 5'"); }
    #[test] fn select_allowed()                { assert_allows("psql -c 'SELECT * FROM users'"); }
    #[test] fn create_table_allowed()          { assert_allows("psql -c 'CREATE TABLE new_table (id int)'"); }
    #[test] fn insert_allowed()                { assert_allows("psql -c 'INSERT INTO users VALUES (1)'"); }

    // ── SQL escaping ────────────────────────────────────────────

    #[test] fn drop_table_single_quotes()  { assert_blocks("psql -c 'DROP TABLE users'"); }
    #[test] fn drop_table_double_quotes()  { assert_blocks(r#"psql -c "DROP TABLE users""#); }
    #[test] fn drop_table_heredoc()        { assert_blocks("psql <<EOF\nDROP TABLE users;\nEOF"); }
    #[test] fn drop_table_pipe()           { assert_blocks("echo 'DROP TABLE users' | psql"); }
    #[test] fn drop_table_e_flag()         { assert_blocks("mysql -e 'DROP TABLE users'"); }
    #[test] fn drop_table_multiline()      { assert_blocks("psql -c '\nDROP TABLE\nusers\n'"); }
    #[test] fn truncate_semicolon()        { assert_blocks("psql -c 'TRUNCATE TABLE logs;'"); }
    #[test] fn delete_from_semicolon()     { assert_blocks("psql -c 'DELETE FROM users;'"); }
    #[test] fn select_star_not_blocked()   { assert_allows("psql -c 'SELECT * FROM users'"); }
    #[test] fn create_not_blocked()        { assert_allows("psql -c 'CREATE TABLE t (id int)'"); }
    #[test] fn alter_add_col_allowed()     { assert_allows("psql -c 'ALTER TABLE t ADD COLUMN name text'"); }

    // ── Kubernetes ──────────────────────────────────────────────

    #[test] fn kubectl_delete_ns_blocked()     { assert_blocks("kubectl delete namespace production"); }
    #[test] fn kubectl_delete_ns_short()       { assert_blocks("kubectl delete ns staging"); }
    #[test] fn kubectl_delete_all_blocked()    { assert_blocks("kubectl delete pods --all"); }
    #[test] fn kubectl_delete_pod_allowed()    { assert_allows("kubectl delete pod stuck-pod -n staging"); }
    #[test] fn kubectl_get_allowed()           { assert_allows("kubectl get pods -n production"); }
    #[test] fn helm_uninstall_prod_blocked()   { assert_blocks("helm uninstall myapp -n production"); }
    #[test] fn helm_uninstall_staging_allowed() { assert_allows("helm uninstall myapp -n staging"); }

    // ── Nix ─────────────────────────────────────────────────────

    #[test] fn nix_gc_delete_warned()    { assert_warns("nix-collect-garbage -d"); }
    #[test] fn nix_store_gc_warned()     { assert_warns("nix store gc"); }
    #[test] fn nix_build_allowed()       { assert_allows("nix build .#default"); }

    // ── Docker ──────────────────────────────────────────────────

    #[test] fn docker_system_prune_warned()  { assert_warns("docker system prune -af"); }
    #[test] fn docker_volume_prune_warned()  { assert_warns("docker volume prune -f"); }
    #[test] fn docker_build_allowed()        { assert_allows("docker build -t myimage ."); }

    // ── Secrets ─────────────────────────────────────────────────

    #[test] fn sops_decrypt_pipe_warned()    { assert_warns("sops -d secrets.yaml | cat"); }
    #[test] fn sops_decrypt_file_allowed()   { assert_allows("sops -d secrets.yaml > decrypted.yaml"); }
    #[test] fn echo_token_warned()           { assert_warns("echo $GITHUB_TOKEN"); }
    #[test] fn echo_normal_allowed()         { assert_allows("echo hello world"); }

    // ── Terraform ───────────────────────────────────────────────

    #[test] fn terraform_destroy_blocked()      { assert_blocks("terraform destroy"); }
    #[test] fn terraform_apply_auto_warned()    { assert_warns("terraform apply -auto-approve"); }
    #[test] fn terraform_plan_allowed()         { assert_allows("terraform plan"); }
    #[test] fn terraform_apply_allowed()        { assert_allows("terraform apply"); }
    #[test] fn terraform_force_unlock_blocked() { assert_blocks("terraform force-unlock abc123"); }
    #[test] fn terraform_state_rm_blocked()     { assert_blocks("terraform state rm aws_instance.web"); }
    #[test] fn terraform_state_list_allowed()   { assert_allows("terraform state list"); }
    #[test] fn pulumi_destroy_blocked()         { assert_blocks("pulumi destroy"); }
    #[test] fn pulumi_up_allowed()              { assert_allows("pulumi up"); }

    // ── FluxCD ──────────────────────────────────────────────────

    #[test] fn flux_uninstall_blocked()         { assert_blocks("flux uninstall"); }
    #[test] fn flux_delete_source_warned()      { assert_warns("flux delete source git my-repo"); }
    #[test] fn flux_delete_ks_warned()          { assert_warns("flux delete kustomization my-app"); }
    #[test] fn flux_reconcile_allowed()         { assert_allows("flux reconcile kustomization my-app"); }
    #[test] fn flux_get_allowed()               { assert_allows("flux get kustomizations"); }

    // ── Engine trait ─────────────────────────────────────────────

    #[test]
    fn engine_compiles_all_defaults() {
        let e = engine();
        assert!(e.rule_count() >= 30);
    }

    #[test]
    fn rules_returns_slice() {
        let e = engine();
        let rules: &[Rule] = e.rules();
        assert!(!rules.is_empty());
        assert!(rules.iter().all(|r| r.category == Category::Filesystem
            || r.category == Category::Git
            || r.category == Category::Database
            || r.category == Category::Kubernetes
            || r.category == Category::Nix
            || r.category == Category::Docker
            || r.category == Category::Secrets
            || r.category == Category::Terraform
            || r.category == Category::Flux
        ));
    }

    #[test]
    fn invalid_regex_rejected() {
        let rules = vec![Rule::builder("bad", "[invalid").build()];
        assert!(RegexEngine::new(rules).is_err());
    }

    #[test]
    fn block_takes_priority_over_warn() {
        let rules = vec![
            Rule::builder("warn-rule", r"rm\s+-rf")
                .severity(Severity::Warn)
                .build(),
            Rule::builder("block-rule", r"rm\s+-rf")
                .severity(Severity::Block)
                .build(),
        ];
        let engine = RegexEngine::new(rules).unwrap();
        match engine.check("rm -rf /tmp/test") {
            Decision::Block { rule, .. } => assert_eq!(rule, "block-rule"),
            other => panic!("expected Block, got {other}"),
        }
    }

    // ── Edge cases ───────────────────────────────────────────────

    #[test]
    fn empty_command_allowed() {
        assert_allows("");
    }

    #[test]
    fn whitespace_only_command_allowed() {
        assert_allows("   ");
    }

    #[test]
    fn unicode_safe_command_allowed() {
        assert_allows("echo 'café résumé'");
    }

    #[test]
    fn very_long_safe_command_allowed() {
        let long = format!("cargo {}", "build ".repeat(500));
        assert_allows(&long);
    }

    #[test]
    fn contains_ascii_ci_matches() {
        assert!(contains_ascii_ci(b"hello DROP TABLE world", b"DROP "));
        assert!(contains_ascii_ci(b"hello drop table world", b"DROP "));
        assert!(contains_ascii_ci(b"hello Drop Table world", b"DROP "));
    }

    #[test]
    fn contains_ascii_ci_no_match() {
        assert!(!contains_ascii_ci(b"hello world", b"DROP "));
        assert!(!contains_ascii_ci(b"DROPX", b"DROP "));
    }

    #[test]
    fn contains_ascii_ci_empty() {
        assert!(contains_ascii_ci(b"anything", b""));
        assert!(!contains_ascii_ci(b"", b"DROP "));
    }

    // ── Display ──────────────────────────────────────────────────

    #[test]
    fn decision_display_allow() {
        assert_eq!(Decision::Allow.to_string(), "allow");
    }

    #[test]
    fn decision_display_block() {
        let d = Decision::Block {
            rule: "test".into(),
            message: "msg".into(),
        };
        assert_eq!(d.to_string(), "block [test]: msg");
    }

    #[test]
    fn decision_display_warn() {
        let d = Decision::Warn {
            rule: "test".into(),
            message: "msg".into(),
        };
        assert_eq!(d.to_string(), "warn [test]: msg");
    }

    #[test]
    fn severity_display() {
        assert_eq!(Severity::Block.to_string(), "block");
        assert_eq!(Severity::Warn.to_string(), "warn");
    }

    #[test]
    fn category_display() {
        assert_eq!(Category::Filesystem.to_string(), "filesystem");
        assert_eq!(Category::Git.to_string(), "git");
        assert_eq!(Category::Cloud.to_string(), "cloud");
        assert_eq!(Category::Nosql.to_string(), "nosql");
    }
}
