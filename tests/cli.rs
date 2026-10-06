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
    for suite in ["aws", "gcp", "azure", "process", "network", "nosql"] {
        let src = format!("{}/rules/{suite}.yaml", env!("CARGO_MANIFEST_DIR"));
        if std::path::Path::new(&src).exists() {
            fs::copy(&src, rules_d.join(format!("{suite}.yaml"))).unwrap();
        }
    }
    dir
}

#[test]
fn check_blocks_rm_rf_root() {
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["check"])
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#)
        .assert()
        .failure()
        .stdout(predicate::str::contains("block"));
}

#[test]
fn check_allows_ls() {
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["check"])
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"ls -la"}}"#)
        .assert()
        .success();
}

#[test]
fn check_blocks_drop_table() {
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["check"])
        .write_stdin(
            r#"{"tool_name":"Bash","tool_input":{"command":"psql -c 'DROP TABLE users'"}}"#,
        )
        .assert()
        .failure()
        .stdout(predicate::str::contains("DROP TABLE"));
}

#[test]
fn check_allows_select() {
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["check"])
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"psql -c 'SELECT 1'"}}"#)
        .assert()
        .success();
}

#[test]
fn check_blocks_terraform_destroy() {
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["check"])
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"terraform destroy"}}"#)
        .assert()
        .failure();
}

#[test]
fn check_allows_terraform_plan() {
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["check"])
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"terraform plan"}}"#)
        .assert()
        .success();
}

#[test]
fn check_allows_non_bash_tool() {
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["check"])
        .write_stdin(r#"{"tool_name":"Write","tool_input":{"file_path":"/tmp/test"}}"#)
        .assert()
        .success();
}

#[test]
fn check_allows_empty_input() {
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["check"])
        .write_stdin(r"{}")
        .assert()
        .success();
}

#[test]
fn validate_succeeds_without_config() {
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["validate"])
        .assert()
        .success();
}

#[test]
fn list_shows_rules() {
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["list"])
        .assert()
        .success()
        .stderr(predicate::str::contains("rules active"));
}

// ── Search-nudge / search-advise (Grep|Glob) ────────────────

#[test]
fn search_advise_emits_context_for_grep() {
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["search-advise"])
        .write_stdin(r#"{"tool_name":"Grep","tool_input":{"pattern":"fn main"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::contains("mcp__codesearch__search_exact"))
        // Pins the RETIREMENT, not just the current string: zoekt was retired
        // 2026-08-12 and this assertion is what stops the dead plane coming back.
        .stdout(predicate::str::contains("mcp__zoekt__search").not())
        .stdout(predicate::str::contains("PostToolUse"))
        .stdout(predicate::str::contains("additionalContext"));
}

#[test]
fn search_advise_emits_context_for_glob() {
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["search-advise"])
        .write_stdin(r#"{"tool_name":"Glob","tool_input":{"glob":"**/*.rs"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::contains("mcp__codesearch__search_exact"))
        .stdout(predicate::str::contains("mcp__zoekt__search").not());
}

#[test]
fn search_advise_non_search_tool_is_silent() {
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["search-advise"])
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn search_advise_bad_json_exits_zero_silent() {
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["search-advise"])
        .write_stdin("this is not json")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn search_nudge_never_denies() {
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["search-nudge"])
        .write_stdin(r#"{"tool_name":"Grep","tool_input":{"pattern":"SomeSymbol"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::contains("deny").not())
        .stdout(predicate::str::contains("PreToolUse"));
}

#[test]
fn search_nudge_bad_json_exits_zero_silent() {
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["search-nudge"])
        .write_stdin("not json at all")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn search_nudge_non_search_tool_is_silent() {
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["search-nudge"])
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

// ── Suite loading via rules.d/ ──────────────────────────────

#[test]
fn suites_load_via_env() {
    let dir = setup_with_suites();
    // Point XDG_CONFIG_HOME to our temp dir so guardrail finds rules.d/
    Command::cargo_bin("guardrail").unwrap()
        .args(["check"])
        .env("XDG_CONFIG_HOME", dir.path())
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"gcloud compute instances delete my-instance --zone us-central1-a"}}"#)
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
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["check"])
        .write_stdin(r#"{"tool_name":"mcp__github__get_me","tool_input":{"reason":"check auth"}}"#)
        .assert()
        .success();
}

#[test]
fn read_tool_passes_through() {
    Command::cargo_bin("guardrail")
        .unwrap()
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
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["check"])
        .write_stdin(
            r#"{"tool_name":"Bash","tool_input":{"command":"bash /tmp/guardrail-test-evil.sh"}}"#,
        )
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
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["check"])
        .write_stdin(
            r#"{"tool_name":"Bash","tool_input":{"command":"bash /tmp/guardrail-test-safe.sh"}}"#,
        )
        .assert()
        .success();
}

#[test]
fn nosql_suite_blocks_flushall() {
    let dir = setup_with_suites();
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["check"])
        .env("XDG_CONFIG_HOME", dir.path())
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"redis-cli FLUSHALL"}}"#)
        .assert()
        .failure();
}

// ── Invalid / malformed input ─────────────────────────────

#[test]
fn check_invalid_json_fails() {
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["check"])
        .write_stdin("this is not json")
        .assert()
        .failure();
}

#[test]
fn check_null_tool_name_allows() {
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["check"])
        .write_stdin(r#"{"tool_name": null, "tool_input": null}"#)
        .assert()
        .success();
}

// ── Compile command ─────────────────────────────────────────

#[test]
fn compile_succeeds() {
    let cache_dir = TempDir::new().unwrap();
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["compile"])
        .env("XDG_CACHE_HOME", cache_dir.path())
        .assert()
        .success()
        .stderr(predicate::str::contains("compiled"));
}

#[test]
fn compile_creates_cache_file() {
    let cache_dir = TempDir::new().unwrap();
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["compile"])
        .env("XDG_CACHE_HOME", cache_dir.path())
        .assert()
        .success();
    let cache_path = cache_dir.path().join("guardrail/compiled.json");
    assert!(
        cache_path.exists(),
        "compile should create cache file at {}",
        cache_path.display()
    );
}

// ── Validate command ────────────────────────────────────────

#[test]
fn validate_with_valid_config() {
    let dir = TempDir::new().unwrap();
    let config_dir = dir.path().join("guardrail");
    fs::create_dir_all(&config_dir).unwrap();
    fs::write(
        config_dir.join("guardrail.yaml"),
        r"
disabledRules:
  - rm-rf-root
",
    )
    .unwrap();

    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["validate"])
        .env("XDG_CONFIG_HOME", dir.path())
        .assert()
        .success()
        .stderr(predicate::str::contains("config valid"));
}

// ── List command ────────────────────────────────────────────

#[test]
fn list_shows_block_and_warn_rules() {
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["list"])
        .assert()
        .success()
        .stderr(predicate::str::contains("BLOCK").or(predicate::str::contains("WARN")));
}

#[test]
fn list_shows_rule_count() {
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["list"])
        .assert()
        .success()
        .stderr(predicate::str::contains("rules active"));
}

// ── Process suite rules via CLI ─────────────────────────────

#[test]
fn process_suite_blocks_shutdown() {
    let dir = setup_with_suites();
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["check"])
        .env("XDG_CONFIG_HOME", dir.path())
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"shutdown -h now"}}"#)
        .assert()
        .failure();
}

#[test]
fn network_suite_blocks_iptables_flush() {
    let dir = setup_with_suites();
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["check"])
        .env("XDG_CONFIG_HOME", dir.path())
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"iptables -F"}}"#)
        .assert()
        .failure();
}

// ── SQL comment bypass via CLI ──────────────────────────────

#[test]
fn check_blocks_sql_comment_bypass() {
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["check"])
        .write_stdin(
            r#"{"tool_name":"Bash","tool_input":{"command":"psql -c 'DROP/**/TABLE users'"}}"#,
        )
        .assert()
        .failure()
        .stdout(predicate::str::contains("block"));
}

// ── Nix store path normalization via CLI ─────────────────────

#[test]
fn check_blocks_nix_wrapped_rm() {
    Command::cargo_bin("guardrail").unwrap()
        .args(["check"])
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"/nix/store/abc123-coreutils-9.0/bin/rm -rf /"}}"#)
        .assert()
        .failure();
}

#[test]
fn check_allows_nix_safe_command() {
    Command::cargo_bin("guardrail").unwrap()
        .args(["check"])
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"/nix/store/abc-foo-1.0/bin/crate2nix generate"}}"#)
        .assert()
        .success();
}

// ── Force push variants via CLI ─────────────────────────────

#[test]
fn check_blocks_force_push_main() {
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["check"])
        .write_stdin(
            r#"{"tool_name":"Bash","tool_input":{"command":"git push --force origin main"}}"#,
        )
        .assert()
        .failure();
}

#[test]
fn check_allows_force_push_feature() {
    Command::cargo_bin("guardrail").unwrap()
        .args(["check"])
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"git push --force origin feature-xyz"}}"#)
        .assert()
        .success();
}

// ── Config disabling rules via CLI ──────────────────────────

#[test]
fn disabled_rule_allows_previously_blocked() {
    let dir = TempDir::new().unwrap();
    let config_dir = dir.path().join("guardrail");
    fs::create_dir_all(&config_dir).unwrap();
    fs::write(
        config_dir.join("guardrail.yaml"),
        r"
disabledRules:
  - rm-rf-root
",
    )
    .unwrap();

    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["check"])
        .env("XDG_CONFIG_HOME", dir.path())
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#)
        .assert()
        .success();
}

#[test]
fn disabled_category_allows_all_rules_in_category() {
    let dir = TempDir::new().unwrap();
    let config_dir = dir.path().join("guardrail");
    fs::create_dir_all(&config_dir).unwrap();
    fs::write(
        config_dir.join("guardrail.yaml"),
        r"
categories:
  filesystem: false
",
    )
    .unwrap();

    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["check"])
        .env("XDG_CONFIG_HOME", dir.path())
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#)
        .assert()
        .success();
}

fn hook_config(yaml: &str) -> (TempDir, TempDir) {
    let dir = TempDir::new().unwrap();
    let config_dir = dir.path().join("guardrail");
    fs::create_dir_all(&config_dir).unwrap();
    fs::write(config_dir.join("guardrail.yaml"), yaml).unwrap();
    (dir, TempDir::new().unwrap())
}

fn guardrail_in(config: &TempDir, cache: &TempDir, args: &[&str]) -> Command {
    let mut cmd = Command::cargo_bin("guardrail").unwrap();
    cmd.args(args)
        .env("XDG_CONFIG_HOME", config.path())
        .env("XDG_CACHE_HOME", cache.path());
    cmd
}

const RM_ROOT: &str =
    r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
const GREP_CALL: &str =
    r#"{"hook_event_name":"PostToolUse","tool_name":"Grep","tool_input":{"pattern":"x"}}"#;

#[test]
fn hook_with_no_actions_is_a_silent_no_op_for_every_event() {
    let (config, cache) = hook_config("categories: {}\n");
    for event in [
        "PreToolUse",
        "PostToolUse",
        "UserPromptSubmit",
        "Notification",
        "Stop",
        "SubagentStop",
        "PreCompact",
        "SessionStart",
        "SessionEnd",
    ] {
        guardrail_in(&config, &cache, &["hook", event])
            .write_stdin(RM_ROOT)
            .assert()
            .success()
            .stdout(predicate::str::is_empty());
    }
}

#[test]
fn hook_for_an_unknown_event_is_silent() {
    let (config, cache) = hook_config("hooks:\n  NotAnEvent:\n    - action: check\n");
    guardrail_in(&config, &cache, &["hook", "NotAnEvent"])
        .write_stdin(RM_ROOT)
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn hook_check_action_blocks_like_check() {
    let (config, cache) =
        hook_config("hooks:\n  PreToolUse:\n    - action: check\n      matcher: Bash\n");
    let direct = guardrail_in(&config, &cache, &["check"])
        .write_stdin(RM_ROOT)
        .output()
        .unwrap();
    let via_hook = guardrail_in(&config, &cache, &["hook", "PreToolUse"])
        .write_stdin(RM_ROOT)
        .output()
        .unwrap();
    assert_eq!(direct.status.code(), Some(1));
    assert_eq!(via_hook.status.code(), direct.status.code());
    assert_eq!(via_hook.stdout, direct.stdout);
    guardrail_in(&config, &cache, &["hook", "PreToolUse"])
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"ls -la"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn hook_search_advise_matches_the_standalone_subcommand_byte_for_byte() {
    let (config, cache) = hook_config(
        "hooks:\n  PostToolUse:\n    - action: searchAdvise\n      matcher: Grep|Glob\n",
    );
    let direct = guardrail_in(&config, &cache, &["search-advise"])
        .write_stdin(GREP_CALL)
        .output()
        .unwrap();
    let via_hook = guardrail_in(&config, &cache, &["hook", "PostToolUse"])
        .write_stdin(GREP_CALL)
        .output()
        .unwrap();
    assert!(direct.status.success() && via_hook.status.success());
    let parse = |b: &[u8]| serde_json::from_slice::<serde_json::Value>(b).unwrap();
    assert_eq!(parse(&via_hook.stdout), parse(&direct.stdout));
}

#[test]
fn hook_search_nudge_and_input_limit_and_mint_advise_actions() {
    let (config, cache) = hook_config(
        r"
toolInputLimits:
  - name: short-comment
    tools: [mcp__x__comment]
    field: body
    maxChars: 5
    message: keep it short
hooks:
  PreToolUse:
    - action: searchNudge
      matcher: Grep|Glob
    - action: inputLimit
      matcher: mcp__x__comment
  PostToolUse:
    - action: mintAdvise
      matcher: Bash|Write
",
    );
    guardrail_in(&config, &cache, &["hook", "PreToolUse"])
        .write_stdin(r#"{"tool_name":"Grep","tool_input":{"pattern":"x"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""hookEventName":"PreToolUse""#));
    guardrail_in(&config, &cache, &["hook", "PreToolUse"])
        .write_stdin(r#"{"tool_name":"mcp__x__comment","tool_input":{"body":"far too long"}}"#)
        .assert()
        .code(1)
        .stdout(predicate::str::contains("short-comment"));
    guardrail_in(&config, &cache, &["hook", "PostToolUse"])
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"mkdir -p /tmp/nowhere/code/github/pleme-io/zz-unminted-name"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::contains("/naming"));
}

#[test]
fn hook_exec_action_passes_its_decision_through() {
    let (config, cache) = hook_config(
        "hooks:\n  Stop:\n    - action: exec\n      command: [sh, -c, 'cat >/dev/null; echo stop-refused >&2; exit 2']\n",
    );
    guardrail_in(&config, &cache, &["hook", "Stop"])
        .write_stdin(r#"{"hook_event_name":"Stop"}"#)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("stop-refused"));
}

#[test]
fn validate_refuses_a_bad_hook_entry() {
    let (config, cache) = hook_config("hooks:\n  Stop:\n    - action: exec\n      command: []\n");
    guardrail_in(&config, &cache, &["validate"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("hooks.Stop[0]"));
    let (config, cache) =
        hook_config("hooks:\n  Stop:\n    - action: exec\n      command: [/usr/bin/true]\n");
    guardrail_in(&config, &cache, &["validate"])
        .assert()
        .success();
}

fn windowed_config(dir: &TempDir, window_file: &str) {
    let config_dir = dir.path().join("guardrail");
    fs::create_dir_all(&config_dir).unwrap();
    fs::write(
        config_dir.join("guardrail.yaml"),
        format!(
            r#"
extraRules:
  - name: team-live-cordon
    pattern: "kubectl\\s+--context\\s+team-live\\S*\\s+cordon"
    severity: block
    message: "a live cordon only inside a window"
    category: team
    window: team-live
changeWindowFiles:
  - {window_file}
"#
        ),
    )
    .unwrap();
}

const LIVE_CORDON: &str = r#"{"tool_name":"Bash","tool_input":{"command":"kubectl --context team-live-1 cordon node-1"}}"#;

#[test]
fn a_window_from_a_window_file_opens_its_tagged_rule() {
    let dir = TempDir::new().unwrap();
    windowed_config(&dir, "windows.json");
    fs::write(
        dir.path().join("guardrail/windows.json"),
        r#"{"changeWindows":[{"name":"ASM-1","tag":"team-live","start":"2000-01-01T00:00:00Z","end":"2999-01-01T00:00:00Z"}]}"#,
    )
    .unwrap();
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["check"])
        .env("XDG_CONFIG_HOME", dir.path())
        .write_stdin(LIVE_CORDON)
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "allowed inside change window ASM-1",
        ));
}

#[test]
fn a_missing_window_file_keeps_the_tagged_rule_closed_and_names_the_file() {
    let dir = TempDir::new().unwrap();
    windowed_config(&dir, "absent.json");
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["check"])
        .env("XDG_CONFIG_HOME", dir.path())
        .write_stdin(LIVE_CORDON)
        .assert()
        .failure()
        .stdout(predicate::str::contains("absent.json"));
}

#[test]
fn validate_does_not_fail_on_an_unread_window_file() {
    let dir = TempDir::new().unwrap();
    windowed_config(&dir, "absent.json");
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["validate"])
        .env("XDG_CONFIG_HOME", dir.path())
        .env("XDG_CACHE_HOME", dir.path())
        .assert()
        .success()
        .stderr(predicate::str::contains("window file not read"));
}

const SCOPED: &str = r#"
extraRules:
  - name: akl-force-push
    pattern: 'git\s+push\b.*(--force|\s-f\b)'
    severity: block
    message: "no force push in akeylesslabs"
    category: git
    cwd: "/akeylesslabs/"
    examples:
      block: [{input: "git push -f origin x", cwd: "/c/akeylesslabs/r"}]
      allow: [{input: "git push -f origin x", cwd: "/c/pleme-io/r"}]
  - name: claude-files
    pattern: '^/Users/[^/]+/\.claude/(skills|CLAUDE\.md|settings\.json)'
    severity: block
    message: "edit the blackmatter source"
    category: claude
    tools: [Write, Edit]
    field: file_path
    examples:
      block: [/Users/x/.claude/settings.json, {input: /Users/x/.claude/skills/a/SKILL.md, tool: Edit}]
      allow: [/Users/x/code/a.rs]
  - name: ai-trailer
    pattern: '(?i)co-authored-by:\s*claude|generated with \[?claude'
    severity: block
    message: "no AI attribution"
    category: attribution
    tools: [mcp__github__create_pull_request, mcp__github__update_pull_request]
    field: body
    examples:
      block: ["Co-Authored-By: Claude <noreply@anthropic.com>"]
      allow: ["fixes the reconnect"]
"#;

#[test]
fn a_cwd_scoped_rule_blocks_only_under_its_cwd() {
    let (config, cache) = hook_config(SCOPED);
    guardrail_in(&config, &cache, &["check"])
        .write_stdin(r#"{"tool_name":"Bash","cwd":"/Users/x/code/github/akeylesslabs/repo","tool_input":{"command":"git push --force-with-lease origin feat"}}"#)
        .assert()
        .failure()
        .stdout(predicate::str::contains("akl-force-push"));
    guardrail_in(&config, &cache, &["check"])
        .write_stdin(r#"{"tool_name":"Bash","cwd":"/Users/x/code/github/pleme-io/repo","tool_input":{"command":"git push --force-with-lease origin feat"}}"#)
        .assert()
        .success();
}

#[test]
fn a_field_scoped_rule_blocks_write_and_mcp_calls() {
    let (config, cache) = hook_config(SCOPED);
    guardrail_in(&config, &cache, &["check"])
        .write_stdin(r#"{"tool_name":"Write","tool_input":{"file_path":"/Users/x/.claude/CLAUDE.md","content":"x"}}"#)
        .assert()
        .failure()
        .stdout(predicate::str::contains("claude-files"));
    guardrail_in(&config, &cache, &["check"])
        .write_stdin(r#"{"tool_name":"mcp__github__create_pull_request","tool_input":{"title":"t","body":"x\n\nGenerated with [Claude Code](https://claude.com)"}}"#)
        .assert()
        .failure()
        .stdout(predicate::str::contains("ai-trailer"));
    guardrail_in(&config, &cache, &["check"])
        .write_stdin(
            r#"{"tool_name":"Read","tool_input":{"file_path":"/Users/x/.claude/CLAUDE.md"}}"#,
        )
        .assert()
        .success();
}

#[test]
fn validate_runs_scoped_examples_and_checks_hook_registration() {
    let (config, cache) = hook_config(SCOPED);
    guardrail_in(&config, &cache, &["validate"])
        .assert()
        .success();
    guardrail_in(
        &config,
        &cache,
        &["validate", "--hooked-tools", "Bash,Write,Edit"],
    )
    .assert()
    .failure()
    .stderr(predicate::str::contains(
        "not registered for tool mcp__github__create_pull_request",
    ));
    guardrail_in(
        &config,
        &cache,
        &[
            "validate",
            "--hooked-tools",
            "Bash,Write,Edit,mcp__github__create_pull_request,mcp__github__update_pull_request",
        ],
    )
    .assert()
    .success();
    let broken = SCOPED.replace("cwd: \"/c/pleme-io/r\"", "cwd: \"/c/akeylesslabs/q\"");
    let (config, cache) = hook_config(&broken);
    guardrail_in(&config, &cache, &["validate"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "akl-force-push: allow example matches",
        ));
}

#[test]
fn validate_refuses_an_unknown_key_and_check_keeps_the_rest() {
    let (config, cache) = hook_config("disabledRule: [rm-rf-root]\ncategories: {}\n");
    guardrail_in(&config, &cache, &["validate"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("key disabledRule"));
    guardrail_in(&config, &cache, &["check"])
        .write_stdin(RM_ROOT)
        .assert()
        .failure()
        .stdout(predicate::str::contains("rm-rf-root"));
}

#[test]
fn validate_refuses_an_unknown_key_in_a_suite_entry_and_keeps_its_siblings() {
    let (config, cache) = hook_config("categories: {}\n");
    let rules_d = config.path().join("guardrail/rules.d");
    fs::create_dir_all(&rules_d).unwrap();
    fs::write(
        rules_d.join("team.yaml"),
        "- {name: typo-rule, pattern: 'zap\\s+all', severity: block, message: m, category: team, test_blok: zap all}\n- {name: kept-rule, pattern: 'zap\\s+one', severity: block, message: m, category: team}\n",
    )
    .unwrap();
    guardrail_in(&config, &cache, &["validate"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("entry 0 (typo-rule)"));
    guardrail_in(&config, &cache, &["list"])
        .assert()
        .success()
        .stderr(
            predicate::str::contains("kept-rule").and(predicate::str::contains("typo-rule").not()),
        );
}

#[test]
fn schema_lists_every_rule_field() {
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["schema"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains(r#""cwd""#)
                .and(predicate::str::contains(r#""changeWindowFiles""#)),
        );
}

#[test]
fn an_invalid_entry_in_a_window_file_never_opens_while_its_siblings_do() {
    let dir = TempDir::new().unwrap();
    windowed_config(&dir, "windows.json");
    fs::write(
        dir.path().join("guardrail/windows.json"),
        r#"{"generatedAt":"x","changeWindows":[{"name":"bad","tag":"team-live","start":"2000-01-01T00:00:00Z","end":"2999-01-01T00:00:00Z","extra":1},{"name":"ASM-2","tag":"team-live","start":"2000-01-01T00:00:00Z","end":"2999-01-01T00:00:00Z"}]}"#,
    )
    .unwrap();
    Command::cargo_bin("guardrail")
        .unwrap()
        .args(["check"])
        .env("XDG_CONFIG_HOME", dir.path())
        .write_stdin(LIVE_CORDON)
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "allowed inside change window ASM-2",
        ));
}
