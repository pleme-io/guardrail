use std::collections::HashSet;

use regex::RegexSet;

use crate::model::{Decision, Rule, Severity};

/// Trait for testable rule matching.
pub trait RuleEngine {
    fn check(&self, command: &str) -> Decision;
    fn rule_count(&self) -> usize;
    fn rules(&self) -> Vec<&Rule>;
}

// ═══════════════════════════════════════════════════════════════════
// Tier 3: Fast reject — skip DFA for 99% of safe commands
// ═══════════════════════════════════════════════════════════════════

/// First-word prefixes that COULD trigger a rule. Commands not starting
/// with one of these skip the DFA entirely (~50ns vs ~3ms).
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

/// Build a HashSet of dangerous prefixes for O(1) lookup.
fn build_prefix_set() -> HashSet<&'static str> {
    DANGEROUS_PREFIXES.iter().copied().collect()
}

/// Fast check: does the command's first word match a dangerous prefix?
/// Returns false (not dangerous) for 99%+ of commands.
#[must_use]
pub fn fast_reject(command: &str, prefixes: &HashSet<&str>) -> bool {
    // Check first two words (handles `sudo rm`, `env VAR=x rm`, etc.)
    let words: Vec<&str> = command.split_whitespace().take(3).collect();
    for word in &words {
        if prefixes.contains(word) || prefixes.iter().any(|p| word.starts_with(p)) {
            return false; // might be dangerous, don't reject
        }
    }
    // Check for SQL keywords that appear mid-command (echo "DROP TABLE" | psql)
    let cmd_upper = command.to_uppercase();
    if cmd_upper.contains("DROP ") || cmd_upper.contains("TRUNCATE ")
        || cmd_upper.contains("DELETE FROM") || cmd_upper.contains("FLUSHALL")
        || cmd_upper.contains("FLUSHDB")
    {
        return false; // might be dangerous
    }
    true // safe — skip DFA
}

// ═══════════════════════════════════════════════════════════════════
// Command normalization — strip nix store path noise
// ═══════════════════════════════════════════════════════════════════

/// Normalize a command by replacing nix store paths with just the binary name.
/// `/nix/store/abc123-pkg-1.0/bin/cmd args` → `cmd args`
/// This prevents false positives from package names in store paths.
#[must_use]
pub fn normalize_command(command: &str) -> String {
    // Replace /nix/store/{hash}-{name}/bin/{binary} with just {binary}
    let re = regex::Regex::new(r"/nix/store/[a-z0-9]+-[^/]+/bin/").unwrap();
    re.replace_all(command, "").to_string()
}

// ═══════════════════════════════════════════════════════════════════
// RegexEngine with fast reject + RegexSet DFA
// ═══════════════════════════════════════════════════════════════════

/// Production engine: fast-reject prefilter + RegexSet single-pass DFA.
///
/// For safe commands (ls, cargo, git status): ~50ns (prefix check only).
/// For potentially dangerous commands: ~3ms (full DFA match).
pub struct RegexEngine {
    set: RegexSet,
    rules: Vec<Rule>,
    prefixes: HashSet<&'static str>,
}

impl RegexEngine {
    /// Compile all rules into a single RegexSet with prefilter.
    ///
    /// # Errors
    ///
    /// Returns an error if any regex pattern is invalid.
    pub fn new(rules: Vec<Rule>) -> anyhow::Result<Self> {
        let patterns: Vec<&str> = rules.iter().map(|r| r.pattern.as_str()).collect();
        let set = RegexSet::new(&patterns)
            .map_err(|e| anyhow::anyhow!("invalid regex in rule set: {e}"))?;
        Ok(Self {
            set,
            rules,
            prefixes: build_prefix_set(),
        })
    }
}

impl RuleEngine for RegexEngine {
    fn check(&self, command: &str) -> Decision {
        // Normalize first (strip nix store paths)
        let normalized = normalize_command(command);

        // Tier 3: fast reject — skip DFA for safe commands
        if fast_reject(&normalized, &self.prefixes) {
            return Decision::Allow;
        }
        let matches: Vec<usize> = self.set.matches(&normalized).into_iter().collect();

        if matches.is_empty() {
            return Decision::Allow;
        }

        // Block takes priority over Warn
        let mut best_block: Option<&Rule> = None;
        let mut best_warn: Option<&Rule> = None;

        for &idx in &matches {
            let rule = &self.rules[idx];
            match rule.severity {
                Severity::Block if best_block.is_none() => best_block = Some(rule),
                Severity::Warn if best_warn.is_none() => best_warn = Some(rule),
                _ => {}
            }
        }

        if let Some(rule) = best_block {
            return Decision::Block {
                rule: rule.name.clone(),
                message: rule.message.clone(),
            };
        }

        if let Some(rule) = best_warn {
            return Decision::Warn {
                rule: rule.name.clone(),
                message: rule.message.clone(),
            };
        }

        Decision::Allow
    }

    fn rule_count(&self) -> usize {
        self.rules.len()
    }

    fn rules(&self) -> Vec<&Rule> {
        self.rules.iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;

    fn engine() -> RegexEngine {
        RegexEngine::new(config::default_rules()).unwrap()
    }

    fn assert_blocks(cmd: &str) {
        let e = engine();
        match e.check(cmd) {
            Decision::Block { .. } => {}
            other => panic!("expected Block for '{cmd}', got {other:?}"),
        }
    }

    fn assert_warns(cmd: &str) {
        let e = engine();
        match e.check(cmd) {
            Decision::Warn { .. } => {}
            other => panic!("expected Warn for '{cmd}', got {other:?}"),
        }
    }

    fn assert_allows(cmd: &str) {
        let e = engine();
        match e.check(cmd) {
            Decision::Allow => {}
            other => panic!("expected Allow for '{cmd}', got {other:?}"),
        }
    }

    // ── Nix store path normalization ─────────────────────────────

    #[test]
    fn normalize_strips_nix_store_path() {
        assert_eq!(
            normalize_command("/nix/store/abc123-pkg-1.0/bin/guardrail check"),
            "guardrail check"
        );
    }

    #[test]
    fn normalize_strips_multiple_store_paths() {
        assert_eq!(
            normalize_command("/nix/store/abc-foo-1.0/bin/cmd1 && /nix/store/def-bar-2.0/bin/cmd2"),
            "cmd1 && cmd2"
        );
    }

    #[test]
    fn normalize_preserves_normal_commands() {
        assert_eq!(normalize_command("ls -la"), "ls -la");
        assert_eq!(normalize_command("cargo test"), "cargo test");
    }

    #[test]
    fn nix_shell_wrapped_mkfs_not_blocked() {
        // nix shell wraps commands with store paths — mkfs in a package name shouldn't trigger
        let cmd = "/nix/store/abc123-e2fsprogs-1.47/bin/crate2nix generate";
        let e = engine();
        match e.check(cmd) {
            Decision::Allow => {}
            other => panic!("nix store path should not trigger: {other:?}"),
        }
    }

    #[test]
    fn actual_mkfs_still_blocked() {
        assert_blocks("mkfs.ext4 /dev/sda1");
        assert_blocks("sudo mkfs.ext4 /dev/sda1");
    }

    #[test]
    fn nix_store_path_with_real_danger() {
        // Even through a nix store path, if the binary IS dangerous, block it
        assert_blocks("/nix/store/abc123-coreutils-9.0/bin/rm -rf /");
    }

    // ── Fast reject ─────────────────────────────────────────────

    #[test]
    fn safe_commands_fast_rejected() {
        let prefixes = build_prefix_set();
        assert!(fast_reject("ls -la", &prefixes));
        assert!(fast_reject("cargo test", &prefixes));
        assert!(fast_reject("cat file.txt", &prefixes));
        assert!(fast_reject("grep -r pattern .", &prefixes));
        assert!(fast_reject("rg pattern .", &prefixes));
        assert!(fast_reject("fd -e rs", &prefixes));
        assert!(fast_reject("head -5 file", &prefixes));
        assert!(fast_reject("wc -l file", &prefixes));
    }

    #[test]
    fn dangerous_prefixes_not_rejected() {
        let prefixes = build_prefix_set();
        assert!(!fast_reject("rm -rf /", &prefixes));
        assert!(!fast_reject("git push --force", &prefixes));
        assert!(!fast_reject("kubectl delete namespace prod", &prefixes));
        assert!(!fast_reject("terraform destroy", &prefixes));
        assert!(!fast_reject("aws ec2 terminate-instances", &prefixes));
    }

    #[test]
    fn piped_sql_not_rejected() {
        let prefixes = build_prefix_set();
        // echo is in prefixes, but also check SQL keywords mid-command
        assert!(!fast_reject("echo 'DROP TABLE users' | psql", &prefixes));
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

    // ── Engine ──────────────────────────────────────────────────

    #[test]
    fn engine_compiles_all_defaults() {
        let e = engine();
        assert!(e.rule_count() >= 30);
    }

    #[test]
    fn invalid_regex_rejected() {
        use crate::model::{Category, Severity};
        let rules = vec![Rule {
            name: "bad".into(),
            pattern: "[invalid".into(),
            severity: Severity::Block,
            message: "test".into(),
            category: Category::Filesystem,
        }];
        assert!(RegexEngine::new(rules).is_err());
    }

    #[test]
    fn block_takes_priority_over_warn() {
        use crate::model::{Category, Severity};
        let rules = vec![
            Rule {
                name: "warn-rule".into(),
                pattern: r"rm\s+-rf".into(),
                severity: Severity::Warn,
                message: "warning".into(),
                category: Category::Filesystem,
            },
            Rule {
                name: "block-rule".into(),
                pattern: r"rm\s+-rf".into(),
                severity: Severity::Block,
                message: "blocked".into(),
                category: Category::Filesystem,
            },
        ];
        let engine = RegexEngine::new(rules).unwrap();
        match engine.check("rm -rf /tmp/test") {
            Decision::Block { rule, .. } => assert_eq!(rule, "block-rule"),
            other => panic!("expected Block, got {other:?}"),
        }
    }
}
