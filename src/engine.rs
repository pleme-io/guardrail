use regex::RegexSet;

use crate::model::{Decision, Rule, Severity};

/// Trait for testable rule matching.
pub trait RuleEngine {
    fn check(&self, command: &str) -> Decision;
    fn rule_count(&self) -> usize;
    fn rules(&self) -> Vec<&Rule>;
}

/// Production engine using RegexSet — matches ALL patterns in a single
/// pass through the input. O(input_length), NOT O(pattern_count).
///
/// At 10,000 rules this is orders of magnitude faster than linear scan.
pub struct RegexEngine {
    /// The compiled RegexSet — one DFA for all patterns.
    set: RegexSet,
    /// Rules in the same order as the RegexSet patterns.
    rules: Vec<Rule>,
}

impl RegexEngine {
    /// Compile all rules into a single RegexSet.
    ///
    /// # Errors
    ///
    /// Returns an error if any regex pattern is invalid.
    pub fn new(rules: Vec<Rule>) -> anyhow::Result<Self> {
        let patterns: Vec<&str> = rules.iter().map(|r| r.pattern.as_str()).collect();
        let set = RegexSet::new(&patterns)
            .map_err(|e| anyhow::anyhow!("invalid regex in rule set: {e}"))?;
        Ok(Self { set, rules })
    }
}

impl RuleEngine for RegexEngine {
    fn check(&self, command: &str) -> Decision {
        let matches: Vec<usize> = self.set.matches(command).into_iter().collect();

        if matches.is_empty() {
            return Decision::Allow;
        }

        // Return the highest-severity match (Block > Warn).
        // Among same severity, return the first matched rule.
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

    // ── Terraform / IaC ────────────────────────────────────────

    #[test] fn terraform_destroy_blocked()      { assert_blocks("terraform destroy"); }
    #[test] fn terraform_apply_auto_warned()    { assert_warns("terraform apply -auto-approve"); }
    #[test] fn terraform_plan_allowed()         { assert_allows("terraform plan"); }
    #[test] fn terraform_apply_allowed()        { assert_allows("terraform apply"); }
    #[test] fn terraform_force_unlock_blocked() { assert_blocks("terraform force-unlock abc123"); }
    #[test] fn terraform_state_rm_blocked()     { assert_blocks("terraform state rm aws_instance.web"); }
    #[test] fn terraform_state_list_allowed()   { assert_allows("terraform state list"); }
    #[test] fn pulumi_destroy_blocked()         { assert_blocks("pulumi destroy"); }
    #[test] fn pulumi_up_allowed()              { assert_allows("pulumi up"); }

    // ── Cloud CLI — tested via suite loading in config tests ────

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

    // ── RegexSet behavior ───────────────────────────────────────

    #[test]
    fn block_takes_priority_over_warn() {
        use crate::model::{Category, Severity};
        let rules = vec![
            Rule {
                name: "warn-rule".into(),
                pattern: "dangerous".into(),
                severity: Severity::Warn,
                message: "warning".into(),
                category: Category::Filesystem,
            },
            Rule {
                name: "block-rule".into(),
                pattern: "dangerous".into(),
                severity: Severity::Block,
                message: "blocked".into(),
                category: Category::Filesystem,
            },
        ];
        let engine = RegexEngine::new(rules).unwrap();
        match engine.check("dangerous command") {
            Decision::Block { rule, .. } => assert_eq!(rule, "block-rule"),
            other => panic!("expected Block, got {other:?}"),
        }
    }
}
