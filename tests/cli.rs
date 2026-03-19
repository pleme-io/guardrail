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

// ── Multi-tool scanning ──────────────────────────────────

#[test]
fn write_with_dangerous_content_warns_not_blocks() {
    // Write tool with "rm -rf /" in content should warn (exit 0), not block
    Command::cargo_bin("guardrail").unwrap()
        .args(["check"])
        .write_stdin("{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"/tmp/evil.sh\",\"content\":\"#!/bin/bash\\nrm -rf /\"}}")
        .assert()
        .success(); // warns to stderr, but exit 0
}

#[test]
fn edit_with_drop_table_warns_not_blocks() {
    Command::cargo_bin("guardrail").unwrap()
        .args(["check"])
        .write_stdin(r#"{"tool_name":"Edit","tool_input":{"file_path":"/tmp/migration.sql","old_string":"pass","new_string":"DROP TABLE users;"}}"#)
        .assert()
        .success(); // downgraded to warn
}

#[test]
fn notebook_with_os_system_warns() {
    Command::cargo_bin("guardrail").unwrap()
        .args(["check"])
        .write_stdin(r#"{"tool_name":"NotebookEdit","tool_input":{"new_source":"import os; os.system('rm -rf /')"}}"#)
        .assert()
        .success(); // downgraded to warn
}

#[test]
fn mcp_tool_with_dangerous_command_blocks() {
    Command::cargo_bin("guardrail").unwrap()
        .args(["check"])
        .write_stdin(r#"{"tool_name":"mcp__kubernetes__k8s-pod-exec","tool_input":{"command":"kubectl delete namespace prod"}}"#)
        .assert()
        .failure()
        .stdout(predicate::str::contains("block"));
}

#[test]
fn mcp_tool_nested_dangerous_string_blocks() {
    // MCP tool with dangerous command buried in nested JSON
    Command::cargo_bin("guardrail").unwrap()
        .args(["check"])
        .write_stdin(r#"{"tool_name":"mcp__fluxcd__apply_kubernetes_manifest","tool_input":{"manifest":"kubectl delete namespace prod","context":"staging"}}"#)
        .assert()
        .failure()
        .stdout(predicate::str::contains("block"));
}

#[test]
fn mcp_safe_tool_allows() {
    Command::cargo_bin("guardrail").unwrap()
        .args(["check"])
        .write_stdin(r#"{"tool_name":"mcp__github__get_me","tool_input":{"reason":"check auth"}}"#)
        .assert()
        .success();
}

#[test]
fn read_tool_passes_through() {
    Command::cargo_bin("guardrail").unwrap()
        .args(["check"])
        .write_stdin(r#"{"tool_name":"Read","tool_input":{"file_path":"/etc/passwd"}}"#)
        .assert()
        .success();
}

#[test]
fn write_safe_content_allows() {
    Command::cargo_bin("guardrail").unwrap()
        .args(["check"])
        .write_stdin("{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"/tmp/hello.txt\",\"content\":\"Hello world\\nThis is safe content\\n\"}}")
        .assert()
        .success();
}

#[test]
fn write_then_bash_chain_blocked() {
    // Step 1: Write a dangerous file — this records in journal
    Command::cargo_bin("guardrail").unwrap()
        .args(["check"])
        .write_stdin("{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"/tmp/guardrail-test-evil.sh\",\"content\":\"#!/bin/bash\\nrm -rf /\"}}")
        .assert()
        .success(); // Write itself is just warned

    // Step 2: Execute that file — should be blocked via journal
    Command::cargo_bin("guardrail").unwrap()
        .args(["check"])
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"bash /tmp/guardrail-test-evil.sh"}}"#)
        .assert()
        .failure()
        .stdout(predicate::str::contains("write-bash-chain"));
}

#[test]
fn write_safe_then_bash_allowed() {
    // Step 1: Write a safe file
    Command::cargo_bin("guardrail").unwrap()
        .args(["check"])
        .write_stdin("{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"/tmp/guardrail-test-safe.sh\",\"content\":\"#!/bin/bash\\necho hello\"}}")
        .assert()
        .success();

    // Step 2: Execute that file — should be allowed (not dangerous)
    Command::cargo_bin("guardrail").unwrap()
        .args(["check"])
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"bash /tmp/guardrail-test-safe.sh"}}"#)
        .assert()
        .success();
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
