use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn setup_with_suites() -> TempDir {
    let dir = TempDir::new().unwrap();
    // XDG_CONFIG_HOME points here, guardrail looks at {XDG}/guardrail/rules.d/
    let guardrail_dir = dir.path().join("guardrail");
    let rules_d = guardrail_dir.join("rules.d");
    fs::create_dir_all(&rules_d).unwrap();
    // Copy suite files
    for suite in ["akeyless", "aws", "gcp", "azure", "process", "network", "nosql"] {
        let src = format!("{}/rules/{suite}.yaml", env!("CARGO_MANIFEST_DIR"));
        if std::path::Path::new(&src).exists() {
            fs::copy(&src, rules_d.join(format!("{suite}.yaml"))).unwrap();
        }
    }
    dir
}

#[test]
fn check_blocks_rm_rf_root() {
    Command::cargo_bin("guardrail").unwrap()
        .args(["check"])
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#)
        .assert()
        .failure()
        .stdout(predicate::str::contains("block"));
}

#[test]
fn check_allows_ls() {
    Command::cargo_bin("guardrail").unwrap()
        .args(["check"])
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"ls -la"}}"#)
        .assert()
        .success();
}

#[test]
fn check_blocks_drop_table() {
    Command::cargo_bin("guardrail").unwrap()
        .args(["check"])
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"psql -c 'DROP TABLE users'"}}"#)
        .assert()
        .failure()
        .stdout(predicate::str::contains("DROP TABLE"));
}

#[test]
fn check_allows_select() {
    Command::cargo_bin("guardrail").unwrap()
        .args(["check"])
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"psql -c 'SELECT 1'"}}"#)
        .assert()
        .success();
}

#[test]
fn check_blocks_terraform_destroy() {
    Command::cargo_bin("guardrail").unwrap()
        .args(["check"])
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"terraform destroy"}}"#)
        .assert()
        .failure();
}

#[test]
fn check_allows_terraform_plan() {
    Command::cargo_bin("guardrail").unwrap()
        .args(["check"])
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"terraform plan"}}"#)
        .assert()
        .success();
}

#[test]
fn check_allows_non_bash_tool() {
    Command::cargo_bin("guardrail").unwrap()
        .args(["check"])
        .write_stdin(r#"{"tool_name":"Write","tool_input":{"file_path":"/tmp/test"}}"#)
        .assert()
        .success();
}

#[test]
fn check_allows_empty_input() {
    Command::cargo_bin("guardrail").unwrap()
        .args(["check"])
        .write_stdin(r#"{}"#)
        .assert()
        .success();
}

#[test]
fn validate_succeeds_without_config() {
    Command::cargo_bin("guardrail").unwrap()
        .args(["validate"])
        .assert()
        .success();
}

#[test]
fn list_shows_rules() {
    Command::cargo_bin("guardrail").unwrap()
        .args(["list"])
        .assert()
        .success()
        .stderr(predicate::str::contains("rules active"));
}

// ── Suite loading via rules.d/ ──────────────────────────────

#[test]
fn suites_load_via_env() {
    let dir = setup_with_suites();
    // Point XDG_CONFIG_HOME to our temp dir so guardrail finds rules.d/
    Command::cargo_bin("guardrail").unwrap()
        .args(["check"])
        .env("XDG_CONFIG_HOME", dir.path())
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"akeyless delete-item --name /my/secret"}}"#)
        .assert()
        .failure()
        .stdout(predicate::str::contains("block"));
}

#[test]
fn aws_suite_blocks_terminate() {
    let dir = setup_with_suites();
    Command::cargo_bin("guardrail").unwrap()
        .args(["check"])
        .env("XDG_CONFIG_HOME", dir.path())
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"aws ec2 terminate-instances --instance-ids i-123"}}"#)
        .assert()
        .failure();
}

#[test]
fn nosql_suite_blocks_flushall() {
    let dir = setup_with_suites();
    Command::cargo_bin("guardrail").unwrap()
        .args(["check"])
        .env("XDG_CONFIG_HOME", dir.path())
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"redis-cli FLUSHALL"}}"#)
        .assert()
        .failure();
}
