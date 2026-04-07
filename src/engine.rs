use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;
use std::sync::LazyLock;

// Re-export generic engine components from hayai
pub use hayai::engine::{
    ChainedNormalizer, IdentityNormalizer, MatchEngine, Normalizer, NullPrefilter, PathNormalizer,
    Prefilter, contains_ascii_ci,
};
use hayai::engine::RegexMatcher;

use crate::model::{Decision, Rule, Severity};

// ═══════════════════════════════════════════════════════════════════
// Domain-specific trait: RuleEngine (returns Decision, not indices)
// ═══════════════════════════════════════════════════════════════════

/// Trait for domain-specific rule matching that returns Decisions.
pub trait RuleEngine {
    fn check(&self, command: &str) -> Decision;
    fn rules(&self) -> &[Rule];
    fn rule_count(&self) -> usize {
        self.rules().len()
    }
}

// ═══════════════════════════════════════════════════════════════════
// Domain-specific normalizer: SqlCommentStripper
// ═══════════════════════════════════════════════════════════════════

static SQL_BLOCK_COMMENT_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"/\*.*?\*/").unwrap());

static SQL_LINE_COMMENT_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    // Match SQL line comments: `-- text` where the text doesn't start with `-`
    // (to avoid matching CLI `-- --flag` patterns).
    // Requires `--` preceded by start-of-line or whitespace, followed by space + non-dash.
    regex::Regex::new(r"(?m)(?:^|[ \t])-- [^-].*$").unwrap()
});

/// Strips SQL block comments (`/* ... */`) and line comments (`-- ...`).
/// Preserves `--` when it appears as a CLI flag (preceded by a word char).
#[derive(Debug, Clone, Copy, Default)]
pub struct SqlCommentStripper;

impl Normalizer for SqlCommentStripper {
    fn normalize<'a>(&self, command: &'a str) -> Cow<'a, str> {
        let has_block = SQL_BLOCK_COMMENT_RE.is_match(command);
        let has_line = SQL_LINE_COMMENT_RE.is_match(command);
        if !has_block && !has_line {
            return Cow::Borrowed(command);
        }
        let mut result = if has_block {
            SQL_BLOCK_COMMENT_RE.replace_all(command, " ").into_owned()
        } else {
            command.to_owned()
        };
        if has_line || SQL_LINE_COMMENT_RE.is_match(&result) {
            result = SQL_LINE_COMMENT_RE.replace_all(&result, "").into_owned();
        }
        Cow::Owned(result)
    }
}

/// Production normalizer: `PathNormalizer` then `SqlCommentStripper`.
pub type ProductionNormalizer = ChainedNormalizer<PathNormalizer, SqlCommentStripper>;

/// Backward-compatible alias for `PathNormalizer`.
pub type NixStoreNormalizer = PathNormalizer;

// ═══════════════════════════════════════════════════════════════════
// Domain-specific prefilter: PrefixPrefilter with guardrail keywords
// ═══════════════════════════════════════════════════════════════════

/// First-word prefixes that COULD trigger a rule.
const DANGEROUS_PREFIXES: &[&str] = &[
    // filesystem
    "rm", "dd", "mkfs", "chmod", "chown", "mv", "truncate", "shred",
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
    // curl/wget (pipe install, elasticsearch)
    "curl", "wget",
    // mysql admin
    "mysqladmin",
    // shell wrappers -- commands that execute other commands
    "sh", "bash", "zsh", "fish", "dash",
    "env", "sudo", "doas", "nohup", "nice", "timeout",
    // eval / indirect execution
    "eval", "xargs", "find",
    // scheduling
    "crontab", "at",
    // disk partitioning
    "fdisk", "parted", "wipefs",
    // sync/publish (supply chain)
    "npm", "cargo", "gem", "pip", "twine",
    // remote sync
    "rsync", "rclone",
    // log wiping
    "journalctl",
    // ssh (remote command execution)
    "ssh",
];

static PREFIX_SET: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| DANGEROUS_PREFIXES.iter().copied().collect());

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
        // Commands starting with $ are variable expansions -- must reach DFA
        let trimmed = command.trim_start();
        if trimmed.starts_with('$') {
            return false;
        }
        // Backtick command substitution -- must reach DFA
        if trimmed.contains('`') {
            return false;
        }
        for (count, word) in command.split_whitespace().enumerate() {
            if count >= 3 {
                break;
            }
            if PREFIX_SET.contains(word) || PREFIX_SET.iter().any(|p| word.starts_with(p)) {
                return false;
            }
        }
        // Zero-alloc SQL keyword scan: byte-level case-insensitive search
        // avoids the String allocation of command.to_uppercase()
        if contains_ascii_ci(command.as_bytes(), b"DROP ")
            || contains_ascii_ci(command.as_bytes(), b"TRUNCATE ")
            || contains_ascii_ci(command.as_bytes(), b"DELETE FROM")
            || contains_ascii_ci(command.as_bytes(), b"REVOKE ")
            || contains_ascii_ci(command.as_bytes(), b"FLUSHALL")
            || contains_ascii_ci(command.as_bytes(), b"FLUSHDB")
            || contains_ascii_ci(command.as_bytes(), b"VACUUM FULL")
            || contains_ascii_ci(command.as_bytes(), b"BASE64")
            || contains_ascii_ci(command.as_bytes(), b"| BASH")
            || contains_ascii_ci(command.as_bytes(), b"| SH")
        {
            return false;
        }
        // SQL comment obfuscation: if command contains block comment or SQL
        // line comment markers, it might be hiding SQL keywords after normalization.
        if command.as_bytes().windows(2).any(|w| w == b"/*")
            || command
                .as_bytes()
                .windows(3)
                .any(|w| w == b"-- " || w == b"--\t")
        {
            return false;
        }
        true
    }
}

// ═══════════════════════════════════════════════════════════════════
// RegexEngine -- wraps hayai::RegexMatcher, adds Decision logic
// ═══════════════════════════════════════════════════════════════════

/// Production rule engine: pluggable normalizer + prefilter + `RegexSet` DFA.
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
pub struct RegexEngine<N: Normalizer = ProductionNormalizer, P: Prefilter = PrefixPrefilter> {
    matcher: RegexMatcher<N, P>,
    rules: Vec<Rule>,
}

impl<N: Normalizer + fmt::Debug, P: Prefilter + fmt::Debug> fmt::Debug for RegexEngine<N, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegexEngine")
            .field("rule_count", &self.rules.len())
            .field("matcher", &self.matcher)
            .finish()
    }
}

/// Default constructor -- production configuration.
impl RegexEngine {
    /// Create an engine with `ProductionNormalizer` + `PrefixPrefilter`.
    ///
    /// # Errors
    ///
    /// Returns an error if any regex pattern is invalid or the compiled
    /// DFA exceeds the 100MB size limit.
    pub fn new(rules: Vec<Rule>) -> anyhow::Result<Self> {
        Self::with_plugins(
            rules,
            ChainedNormalizer {
                first: PathNormalizer,
                second: SqlCommentStripper,
            },
            PrefixPrefilter,
        )
    }
}

impl<N: Normalizer, P: Prefilter> RegexEngine<N, P> {
    /// Create an engine with custom normalizer and prefilter.
    ///
    /// # Errors
    ///
    /// Returns an error if any regex pattern is invalid.
    pub fn with_plugins(rules: Vec<Rule>, normalizer: N, prefilter: P) -> anyhow::Result<Self> {
        let patterns: Vec<String> = rules.iter().map(|r| r.pattern.clone()).collect();
        let matcher = RegexMatcher::with_plugins(patterns, normalizer, prefilter)?;
        Ok(Self { matcher, rules })
    }
}

impl<N: Normalizer, P: Prefilter> RuleEngine for RegexEngine<N, P> {
    fn check(&self, command: &str) -> Decision {
        let matches = self.matcher.check(command);
        if matches.is_empty() {
            return Decision::Allow;
        }

        // Block takes priority -- early-exit on first Block match.
        let mut best_warn: Option<&Rule> = None;

        for idx in matches {
            let rule = &self.rules[idx];
            match rule.severity {
                Severity::Block => {
                    return Decision::Block {
                        rule: rule.name.clone(),
                        message: rule.message.clone(),
                    };
                }
                Severity::Warn if best_warn.is_none() => best_warn = Some(rule),
                Severity::Warn => {}
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

    // -- Normalizer trait -----------------------------------------

    #[test]
    fn path_normalizer_strips_nix_store_path() {
        let n = PathNormalizer;
        let result = n.normalize("/nix/store/abc123-pkg-1.0/bin/guardrail check");
        assert_eq!(&*result, "guardrail check");
        assert!(matches!(result, Cow::Owned(_)));
    }

    #[test]
    fn path_normalizer_borrows_when_no_path() {
        let n = PathNormalizer;
        let result = n.normalize("cargo test");
        assert_eq!(&*result, "cargo test");
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    #[test]
    fn path_normalizer_strips_multiple_nix_paths() {
        let n = PathNormalizer;
        let result =
            n.normalize("/nix/store/abc-foo-1.0/bin/cmd1 && /nix/store/def-bar-2.0/bin/cmd2");
        assert_eq!(&*result, "cmd1 && cmd2");
    }

    #[test]
    fn path_normalizer_strips_usr_bin() {
        let n = PathNormalizer;
        let result = n.normalize("/usr/bin/rm -rf /");
        assert_eq!(&*result, "rm -rf /");
        assert!(matches!(result, Cow::Owned(_)));
    }

    #[test]
    fn path_normalizer_strips_usr_local_bin() {
        let n = PathNormalizer;
        let result = n.normalize("/usr/local/bin/terraform destroy");
        assert_eq!(&*result, "terraform destroy");
    }

    #[test]
    fn path_normalizer_strips_bin() {
        let n = PathNormalizer;
        let result = n.normalize("/bin/rm -rf /");
        assert_eq!(&*result, "rm -rf /");
    }

    #[test]
    fn path_normalizer_strips_sbin() {
        let n = PathNormalizer;
        let result = n.normalize("/sbin/mkfs.ext4 /dev/sda1");
        assert_eq!(&*result, "mkfs.ext4 /dev/sda1");
    }

    #[test]
    fn identity_normalizer_is_noop() {
        let n = IdentityNormalizer;
        let result = n.normalize("anything");
        assert!(matches!(result, Cow::Borrowed("anything")));
    }

    // -- SQL comment stripping ------------------------------------

    #[test]
    fn sql_comment_stripper_block_comment() {
        let n = SqlCommentStripper;
        let result = n.normalize("DELETE/**/FROM users");
        assert_eq!(result.trim(), "DELETE FROM users");
    }

    #[test]
    fn sql_comment_stripper_sneaky_block_comment() {
        let n = SqlCommentStripper;
        let result = n.normalize("DROP/* sneaky */TABLE users");
        assert_eq!(result.trim(), "DROP TABLE users");
    }

    #[test]
    fn sql_comment_stripper_line_comment() {
        let n = SqlCommentStripper;
        let result = n.normalize("DROP TABLE -- this is a comment\nusers");
        // Line comment removed; newline preserved
        assert!(result.contains("DROP TABLE"));
    }

    #[test]
    fn sql_comment_stripper_preserves_cli_flags() {
        let n = SqlCommentStripper;
        let result = n.normalize("cargo build -- --release");
        // `--` preceded by word char 'd' -> not a SQL comment
        assert_eq!(&*result, "cargo build -- --release");
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    #[test]
    fn sql_comment_stripper_no_comments() {
        let n = SqlCommentStripper;
        let result = n.normalize("SELECT * FROM users");
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    // -- ChainedNormalizer / ProductionNormalizer ------------------

    #[test]
    fn chained_normalizer_chains_path_and_sql() {
        let n = ChainedNormalizer { first: PathNormalizer, second: SqlCommentStripper };
        let result = n.normalize("/usr/bin/psql -c 'DROP/**/TABLE users'");
        assert!(result.contains("DROP"));
        assert!(result.contains("TABLE"));
        assert!(!result.contains("/usr/bin/"));
    }

    #[test]
    fn chained_normalizer_borrows_when_clean() {
        let n: ProductionNormalizer = ChainedNormalizer { first: PathNormalizer, second: SqlCommentStripper };
        let result = n.normalize("cargo test");
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    #[test]
    fn chained_normalizer_only_first_transforms() {
        let n = ChainedNormalizer { first: PathNormalizer, second: SqlCommentStripper };
        let result = n.normalize("/usr/bin/ls -la");
        assert_eq!(&*result, "ls -la");
    }

    #[test]
    fn chained_normalizer_only_second_transforms() {
        let n = ChainedNormalizer { first: PathNormalizer, second: SqlCommentStripper };
        let result = n.normalize("DROP/**/TABLE users");
        assert!(result.contains("DROP"));
        assert!(result.contains("TABLE"));
    }

    #[test]
    fn chained_normalizer_identity_is_noop() {
        let n = ChainedNormalizer { first: IdentityNormalizer, second: IdentityNormalizer };
        let result = n.normalize("anything");
        assert!(matches!(result, Cow::Borrowed("anything")));
    }

    // -- Prefilter trait ------------------------------------------

    #[test]
    fn prefix_prefilter_safe_commands() {
        let p = PrefixPrefilter;
        assert!(p.is_safe("ls -la"));
        assert!(p.is_safe("cat file.txt"));
        assert!(p.is_safe("rg pattern ."));
        assert!(p.is_safe("wc -l file"));
        assert!(p.is_safe("head -5 file"));
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

    // -- Engine with plugins --------------------------------------

    #[test]
    fn engine_with_null_prefilter_checks_everything() {
        let rules = config::default_rules();
        let normalizer = ChainedNormalizer { first: PathNormalizer, second: SqlCommentStripper };
        let engine =
            RegexEngine::with_plugins(rules, normalizer, NullPrefilter).unwrap();
        // Even "safe" commands like "ls" reach the DFA -- but no rule matches
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

    // -- Nix store path normalization -----------------------------

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

    #[test]
    fn usr_bin_rm_blocked() {
        assert_blocks("/usr/bin/rm -rf /");
    }

    #[test]
    fn sbin_mkfs_blocked() {
        assert_blocks("/sbin/mkfs.ext4 /dev/sda1");
    }

    #[test]
    fn usr_local_bin_terraform_blocked() {
        assert_blocks("/usr/local/bin/terraform destroy");
    }

    #[test]
    fn bin_rm_blocked() {
        assert_blocks("/bin/rm -rf /");
    }

    // -- Filesystem -----------------------------------------------

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

    // -- Git ------------------------------------------------------

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

    // -- Database -------------------------------------------------

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

    // -- SQL escaping ---------------------------------------------

    #[test] fn drop_table_single_quotes()  { assert_blocks("psql -c 'DROP TABLE users'"); }
    #[test] fn drop_table_double_quotes()  { assert_blocks(r#"psql -c "DROP TABLE users""#); }
    #[test] fn drop_table_heredoc()        { assert_blocks("psql <<EOF\nDROP TABLE users;\nEOF"); }
    #[test] fn drop_table_pipe()           { assert_blocks("echo 'DROP TABLE users' | psql"); }
    #[test] fn drop_table_e_flag()         { assert_blocks("mysql -e 'DROP TABLE users'"); }
    #[test] fn drop_table_multiline()      { assert_blocks("psql -c '\nDROP TABLE\nusers\n'"); }
    #[test] fn truncate_semicolon()        { assert_blocks("psql -c 'TRUNCATE TABLE logs;'"); }
    #[test] fn delete_from_semicolon()     { assert_blocks("psql -c 'DELETE FROM users;'"); }

    // -- SQL comment bypass blocked -------------------------------

    #[test] fn drop_table_block_comment()  { assert_blocks("psql -c 'DROP/**/TABLE users'"); }
    #[test] fn drop_sneaky_comment()       { assert_blocks("psql -c 'DROP/* sneaky */TABLE users'"); }
    #[test] fn delete_block_comment()      { assert_blocks("psql -c 'DELETE/**/FROM users'"); }
    #[test] fn select_star_not_blocked()   { assert_allows("psql -c 'SELECT * FROM users'"); }
    #[test] fn create_not_blocked()        { assert_allows("psql -c 'CREATE TABLE t (id int)'"); }
    #[test] fn alter_add_col_allowed()     { assert_allows("psql -c 'ALTER TABLE t ADD COLUMN name text'"); }

    // -- Kubernetes -----------------------------------------------

    #[test] fn kubectl_delete_ns_blocked()     { assert_blocks("kubectl delete namespace production"); }
    #[test] fn kubectl_delete_ns_short()       { assert_blocks("kubectl delete ns staging"); }
    #[test] fn kubectl_delete_all_blocked()    { assert_blocks("kubectl delete pods --all"); }
    #[test] fn kubectl_delete_pod_allowed()    { assert_allows("kubectl delete pod stuck-pod -n staging"); }
    #[test] fn kubectl_get_allowed()           { assert_allows("kubectl get pods -n production"); }
    #[test] fn helm_uninstall_prod_blocked()   { assert_blocks("helm uninstall myapp -n production"); }
    #[test] fn helm_uninstall_staging_allowed() { assert_allows("helm uninstall myapp -n staging"); }

    // -- Nix ------------------------------------------------------

    #[test] fn nix_gc_delete_warned()    { assert_warns("nix-collect-garbage -d"); }
    #[test] fn nix_store_gc_warned()     { assert_warns("nix store gc"); }
    #[test] fn nix_build_allowed()       { assert_allows("nix build .#default"); }

    // -- Docker ---------------------------------------------------

    #[test] fn docker_system_prune_warned()  { assert_warns("docker system prune -af"); }
    #[test] fn docker_volume_prune_warned()  { assert_warns("docker volume prune -f"); }
    #[test] fn docker_build_allowed()        { assert_allows("docker build -t myimage ."); }

    // -- Secrets --------------------------------------------------

    #[test] fn sops_decrypt_pipe_warned()    { assert_warns("sops -d secrets.yaml | cat"); }
    #[test] fn sops_decrypt_file_allowed()   { assert_allows("sops -d secrets.yaml > decrypted.yaml"); }
    #[test] fn echo_token_warned()           { assert_warns("echo $GITHUB_TOKEN"); }
    #[test] fn echo_normal_allowed()         { assert_allows("echo hello world"); }

    // -- Terraform ------------------------------------------------

    #[test] fn terraform_destroy_blocked()      { assert_blocks("terraform destroy"); }
    #[test] fn terraform_apply_auto_warned()    { assert_warns("terraform apply -auto-approve"); }
    #[test] fn terraform_plan_allowed()         { assert_allows("terraform plan"); }
    #[test] fn terraform_apply_allowed()        { assert_allows("terraform apply"); }
    #[test] fn terraform_force_unlock_blocked() { assert_blocks("terraform force-unlock abc123"); }
    #[test] fn terraform_state_rm_blocked()     { assert_blocks("terraform state rm aws_instance.web"); }
    #[test] fn terraform_state_list_allowed()   { assert_allows("terraform state list"); }
    #[test] fn pulumi_destroy_blocked()         { assert_blocks("pulumi destroy"); }
    #[test] fn pulumi_up_allowed()              { assert_allows("pulumi up"); }

    // -- FluxCD ---------------------------------------------------

    #[test] fn flux_uninstall_blocked()         { assert_blocks("flux uninstall"); }
    #[test] fn flux_delete_source_warned()      { assert_warns("flux delete source git my-repo"); }
    #[test] fn flux_delete_ks_warned()          { assert_warns("flux delete kustomization my-app"); }
    #[test] fn flux_reconcile_allowed()         { assert_allows("flux reconcile kustomization my-app"); }
    #[test] fn flux_get_allowed()               { assert_allows("flux get kustomizations"); }

    // -- Engine trait ---------------------------------------------

    #[test]
    fn engine_compiles_all_defaults() {
        let e = engine();
        assert!(e.rule_count() >= 30);
    }

    #[test]
    fn rules_returns_slice() {
        let e = engine();
        let rules: &[Rule] = e.rules();
        assert!(rules.len() >= 60, "expected 60+ default rules, got {}", rules.len());
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

    // -- Variable expansion ---------------------------------------

    #[test] fn var_as_command_warned()       { assert_warns("$cmd --force"); }
    #[test] fn indirect_eval_var_warned()    { assert_warns(r#"eval "$user_input""#); }
    #[test] fn bash_c_var_warned()           { assert_warns(r#"bash -c "$cmd""#); }
    #[test] fn backtick_rm_warned()          { assert_warns("echo `rm -rf /tmp`"); }
    #[test] fn backtick_date_allowed()       { assert_allows("echo `date`"); }
    #[test] fn echo_dollar_home_allowed()    { assert_allows("echo $HOME"); }

    // -- Prefilter: $ and backtick --------------------------------

    #[test]
    fn prefilter_dollar_not_safe() {
        let p = PrefixPrefilter;
        assert!(!p.is_safe("$cmd --force"));
    }

    #[test]
    fn prefilter_backtick_not_safe() {
        let p = PrefixPrefilter;
        assert!(!p.is_safe("echo `rm -rf /`"));
    }

    #[test]
    fn prefilter_sql_block_comment_not_safe() {
        let p = PrefixPrefilter;
        assert!(!p.is_safe("SELECT /*evil*/ 1"));
    }

    #[test]
    fn prefilter_sql_line_comment_not_safe() {
        let p = PrefixPrefilter;
        assert!(!p.is_safe("SELECT 1 -- comment"));
    }

    #[test]
    fn prefilter_cli_double_dash_is_safe() {
        let p = PrefixPrefilter;
        // `--release` has no space after `--` -> not a SQL comment marker -> safe
        // (using `rg` which is not in the dangerous prefix list)
        assert!(p.is_safe("rg --release pattern ."));
    }

    // -- Edge cases -----------------------------------------------

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
        assert_allows("echo 'cafe resume'");
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

    // -- Engine edge cases ----------------------------------------

    #[test]
    fn empty_rules_engine() {
        let engine = RegexEngine::new(vec![]).unwrap();
        assert!(matches!(engine.check("rm -rf /"), Decision::Allow));
        assert_eq!(engine.rule_count(), 0);
        assert!(engine.rules().is_empty());
    }

    #[test]
    fn warn_only_engine() {
        let rules = vec![
            Rule::builder("w1", r"rm\s+-rf").severity(Severity::Warn).build(),
            Rule::builder("w2", r"delete").severity(Severity::Warn).build(),
        ];
        let engine = RegexEngine::with_plugins(rules, IdentityNormalizer, NullPrefilter).unwrap();
        match engine.check("rm -rf /tmp") {
            Decision::Warn { rule, .. } => assert_eq!(rule, "w1"),
            other => panic!("expected Warn, got {other}"),
        }
    }

    #[test]
    fn multiple_warn_returns_first() {
        let rules = vec![
            Rule::builder("first-warn", r"rm").severity(Severity::Warn).build(),
            Rule::builder("second-warn", r"rm\s+-rf").severity(Severity::Warn).build(),
        ];
        let engine = RegexEngine::with_plugins(rules, IdentityNormalizer, NullPrefilter).unwrap();
        match engine.check("rm -rf /") {
            Decision::Warn { rule, .. } => assert_eq!(rule, "first-warn"),
            other => panic!("expected first Warn, got {other}"),
        }
    }

    #[test]
    fn block_before_warn_in_rule_order() {
        let rules = vec![
            Rule::builder("warn-first", r"terraform").severity(Severity::Warn).build(),
            Rule::builder("block-second", r"terraform\s+destroy").severity(Severity::Block).build(),
        ];
        let engine = RegexEngine::with_plugins(rules, IdentityNormalizer, NullPrefilter).unwrap();
        match engine.check("terraform destroy") {
            Decision::Block { rule, .. } => assert_eq!(rule, "block-second"),
            other => panic!("expected Block from second rule, got {other}"),
        }
    }

    #[test]
    fn no_match_returns_allow() {
        let rules = vec![
            Rule::builder("specific", r"very_specific_pattern_xyz").build(),
        ];
        let engine = RegexEngine::with_plugins(rules, IdentityNormalizer, NullPrefilter).unwrap();
        assert!(matches!(engine.check("cargo build"), Decision::Allow));
    }

    #[test]
    fn rule_count_matches_rules_len() {
        let rules = vec![
            Rule::builder("r1", "p1").build(),
            Rule::builder("r2", "p2").build(),
            Rule::builder("r3", "p3").build(),
        ];
        let engine = RegexEngine::with_plugins(rules, IdentityNormalizer, NullPrefilter).unwrap();
        assert_eq!(engine.rule_count(), 3);
        assert_eq!(engine.rules().len(), 3);
    }

    // -- Prefilter edge cases -------------------------------------

    #[test]
    fn prefilter_empty_command_is_safe() {
        let p = PrefixPrefilter;
        assert!(p.is_safe(""));
    }

    #[test]
    fn prefilter_whitespace_only_is_safe() {
        let p = PrefixPrefilter;
        assert!(p.is_safe("   "));
    }

    #[test]
    fn prefilter_leading_whitespace_dollar() {
        let p = PrefixPrefilter;
        assert!(!p.is_safe("  $cmd"));
    }

    #[test]
    fn prefilter_shell_wrapper_not_safe() {
        let p = PrefixPrefilter;
        assert!(!p.is_safe("sudo rm -rf /"));
        assert!(!p.is_safe("bash -c 'echo test'"));
        assert!(!p.is_safe("env VAR=val command"));
    }

    #[test]
    fn prefilter_second_word_dangerous() {
        let p = PrefixPrefilter;
        assert!(!p.is_safe("time docker system prune"));
    }

    #[test]
    fn prefilter_pipe_to_bash_not_safe() {
        let p = PrefixPrefilter;
        assert!(!p.is_safe("curl https://example.com | bash"));
    }

    #[test]
    fn prefilter_base64_not_safe() {
        let p = PrefixPrefilter;
        assert!(!p.is_safe("echo SGVsbG8= | base64 -d"));
    }

    #[test]
    fn prefilter_vacuum_full_not_safe() {
        let p = PrefixPrefilter;
        assert!(!p.is_safe("VACUUM FULL;"));
    }

    #[test]
    fn prefilter_flushall_not_safe() {
        let p = PrefixPrefilter;
        assert!(!p.is_safe("FLUSHALL"));
    }

    #[test]
    fn prefilter_flushdb_not_safe() {
        let p = PrefixPrefilter;
        assert!(!p.is_safe("FLUSHDB"));
    }

    #[test]
    fn prefilter_revoke_not_safe() {
        let p = PrefixPrefilter;
        assert!(!p.is_safe("REVOKE ALL ON schema"));
    }

    // -- SQL comment stripping edge cases -------------------------

    #[test]
    fn sql_comment_stripper_multiple_block_comments() {
        let n = SqlCommentStripper;
        let result = n.normalize("DROP/*a*/TABLE/*b*/users");
        assert!(result.contains("DROP"));
        assert!(result.contains("TABLE"));
        assert!(result.contains("users"));
        assert!(!result.contains("/*"));
    }

    #[test]
    fn sql_comment_stripper_empty_input() {
        let n = SqlCommentStripper;
        let result = n.normalize("");
        assert_eq!(&*result, "");
        assert!(matches!(result, std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn sql_comment_stripper_only_block_comment() {
        let n = SqlCommentStripper;
        let result = n.normalize("/* only a comment */");
        assert!(!result.contains("/*"));
    }

    // -- Path normalizer edge cases -------------------------------

    #[test]
    fn path_normalizer_multiple_standard_paths() {
        let n = PathNormalizer;
        let result = n.normalize("/usr/bin/git push --force && /sbin/reboot");
        assert_eq!(&*result, "git push --force && reboot");
    }

    #[test]
    fn path_normalizer_empty_input() {
        let n = PathNormalizer;
        let result = n.normalize("");
        assert_eq!(&*result, "");
        assert!(matches!(result, std::borrow::Cow::Borrowed(_)));
    }

    // -- Display --------------------------------------------------

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
