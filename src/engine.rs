use regex::Regex;

use crate::model::{Decision, Rule, Severity};

/// A rule with its regex pre-compiled.
pub struct CompiledRule {
    pub rule: Rule,
    pub regex: Regex,
}

/// Trait for testable rule matching.
pub trait RuleEngine {
    fn check(&self, command: &str) -> Decision;
    fn rule_count(&self) -> usize;
}

/// Production engine: compiles regexes once, matches against all rules.
pub struct RegexEngine {
    rules: Vec<CompiledRule>,
}

impl RegexEngine {
    /// Compile all rules into regexes.
    ///
    /// # Errors
    ///
    /// Returns an error if any regex pattern is invalid.
    pub fn new(rules: Vec<Rule>) -> anyhow::Result<Self> {
        let compiled = rules
            .into_iter()
            .map(|rule| {
                let regex = Regex::new(&rule.pattern)
                    .map_err(|e| anyhow::anyhow!("rule '{}': invalid regex: {e}", rule.name))?;
                Ok(CompiledRule { rule, regex })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Self { rules: compiled })
    }
}

impl RuleEngine for RegexEngine {
    fn check(&self, command: &str) -> Decision {
        for cr in &self.rules {
            if cr.regex.is_match(command) {
                return match cr.rule.severity {
                    Severity::Block => Decision::Block {
                        rule: cr.rule.name.clone(),
                        message: cr.rule.message.clone(),
                    },
                    Severity::Warn => Decision::Warn {
                        rule: cr.rule.name.clone(),
                        message: cr.rule.message.clone(),
                    },
                };
            }
        }
        Decision::Allow
    }

    fn rule_count(&self) -> usize {
        self.rules.len()
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

    // ── Engine ──────────────────────────────────────────────────

    #[test]
    fn engine_compiles_all_defaults() {
        let e = engine();
        assert!(e.rule_count() >= 25);
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
}
