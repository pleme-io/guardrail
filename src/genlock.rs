use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;

use regex::Regex;
use sha2::{Digest, Sha256};

use crate::hook::HookInput;

pub const RULE: &str = "gen-lock-tie";
const GEN_LOCK: &str = "Cargo.gen.lock";

static COMMIT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[;&|(]\s*)git((?:\s+-C\s+\S+)*)\s+commit\b([^;&|)]*)").expect("valid regex")
});

static CD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[;&|(]\s*)(?:cd|pushd)\s+([^\s;&|)]+)").expect("valid regex")
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitCall {
    pub cds: Vec<String>,
    pub dirs: Vec<String>,
    pub all: bool,
}

fn expand_home(path: &str) -> PathBuf {
    match (path.strip_prefix('~'), std::env::var_os("HOME")) {
        (Some(rest), Some(home)) => PathBuf::from(home).join(rest.trim_start_matches('/')),
        _ => PathBuf::from(path),
    }
}

fn unquote(s: &str) -> &str {
    s.trim_matches(|c| c == '"' || c == '\'')
}

fn is_all_flag(token: &str) -> bool {
    if token == "--all" {
        return true;
    }
    let Some(letters) = token.strip_prefix('-') else {
        return false;
    };
    if letters.is_empty()
        || letters.starts_with('-')
        || !letters.chars().all(|c| c.is_ascii_alphabetic())
    {
        return false;
    }
    for c in letters.chars() {
        if c == 'a' {
            return true;
        }
        if matches!(c, 'm' | 'F' | 'C' | 'c' | 't') {
            return false;
        }
    }
    false
}

fn takes_value(token: &str) -> bool {
    matches!(
        token,
        "-m" | "-F" | "-C" | "-c" | "-t" | "--message" | "--file" | "--author" | "--date"
    ) || (token.starts_with('-')
        && !token.starts_with("--")
        && token.len() > 2
        && token.ends_with(['m', 'F', 'C', 'c', 't']))
}

#[must_use]
pub fn parse_commit(command: &str) -> Option<CommitCall> {
    let caps = COMMIT.captures(command)?;
    let start = caps.get(0).map_or(0, |m| m.start());
    let cds = CD
        .captures_iter(&command[..start])
        .map(|c| unquote(&c[1]).to_string())
        .collect();
    let dirs = caps[1]
        .split_whitespace()
        .filter(|t| *t != "-C")
        .map(|t| unquote(t).to_string())
        .collect();
    let mut all = false;
    let mut skip = false;
    for token in caps[2].split_whitespace() {
        if skip {
            skip = false;
            continue;
        }
        if token.starts_with('"') || token.starts_with('\'') {
            continue;
        }
        if is_all_flag(token) {
            all = true;
        }
        skip = takes_value(token);
    }
    Some(CommitCall { cds, dirs, all })
}

fn git(dir: &Path, args: &[&str]) -> Option<Vec<u8>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    out.status.success().then_some(out.stdout)
}

fn read(top: &Path, path: &str, all: bool) -> Option<Vec<u8>> {
    if all {
        std::fs::read(top.join(path)).ok()
    } else {
        git(top, &["cat-file", "blob", &format!(":{path}")])
    }
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tie {
    Fresh,
    Unreadable,
    Invalid,
    Stale(Vec<String>),
}

#[must_use]
pub fn check_repo(dir: &Path, all: bool) -> Tie {
    let Some(top) = git(dir, &["rev-parse", "--show-toplevel"]) else {
        return Tie::Unreadable;
    };
    let top = PathBuf::from(String::from_utf8_lossy(&top).trim());
    if git(&top, &["cat-file", "-e", &format!(":{GEN_LOCK}")]).is_none() {
        return Tie::Unreadable;
    }
    let Some(lock) = read(&top, GEN_LOCK, all) else {
        return Tie::Unreadable;
    };
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&lock) else {
        return Tie::Invalid;
    };
    let mut stale = Vec::new();
    if let Some(want) = json.get("cargo_lock_sha256").and_then(|v| v.as_str()) {
        if read(&top, "Cargo.lock", all).map(|b| digest(&b)).as_deref() != Some(want) {
            stale.push("Cargo.lock".to_string());
        }
    }
    if let Some(manifests) = json.get("manifest_sha256").and_then(|v| v.as_object()) {
        let mut stale_manifests: Vec<&str> = manifests
            .iter()
            .filter(|(path, want)| {
                read(&top, path, all).map(|b| digest(&b)).as_deref() != want.as_str()
            })
            .map(|(path, _)| path.as_str())
            .collect();
        stale_manifests.sort_unstable();
        if !stale_manifests.is_empty() {
            stale.push(format!("manifests: {}", stale_manifests.join(", ")));
        }
    }
    if stale.is_empty() {
        Tie::Fresh
    } else {
        Tie::Stale(stale)
    }
}

#[must_use]
pub fn block(input: &HookInput) -> Option<(String, String)> {
    let command = input.tool_input.as_ref()?.command.as_deref()?;
    let call = parse_commit(command)?;
    let mut dir = PathBuf::from(input.cwd.as_deref().unwrap_or("."));
    for d in &call.cds {
        let next = dir.join(expand_home(d));
        if next.is_dir() {
            dir = next;
        }
    }
    for d in &call.dirs {
        dir = dir.join(d);
    }
    let staged = if call.all { "committed" } else { "staged" };
    match check_repo(&dir, call.all) {
        Tie::Fresh | Tie::Unreadable => None,
        Tie::Invalid => Some((
            RULE.to_string(),
            format!(
                "the {staged} {GEN_LOCK} is not valid JSON: run `gen build .` and `git add {GEN_LOCK}` in this same commit"
            ),
        )),
        Tie::Stale(halves) => Some((
            RULE.to_string(),
            format!(
                "{GEN_LOCK} is stale against the {staged} {}: run `gen build .` and `git add {GEN_LOCK}` in this same commit",
                halves.join(" and ")
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hook::ToolInput;

    fn sh(dir: &Path, args: &[&str]) {
        let ok = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .status()
            .expect("git runs")
            .success();
        assert!(ok, "git {args:?}");
    }

    fn write(dir: &Path, path: &str, body: &str) {
        let p = dir.join(path);
        std::fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
        std::fs::write(p, body).expect("write");
    }

    fn gen_repo() -> tempfile::TempDir {
        let t = tempfile::tempdir().expect("tempdir");
        let d = t.path();
        sh(d, &["init", "-q"]);
        write(d, "Cargo.lock", "lock-v1\n");
        write(d, "Cargo.toml", "[package]\n");
        write(d, "crates/x/Cargo.toml", "[package]\nname = \"x\"\n");
        let lock = serde_json::json!({
            "schema_version": 2,
            "cargo_lock_sha256": digest(b"lock-v1\n"),
            "manifest_sha256": {
                "Cargo.toml": digest(b"[package]\n"),
                "crates/x/Cargo.toml": digest(b"[package]\nname = \"x\"\n"),
            }
        });
        write(d, GEN_LOCK, &lock.to_string());
        sh(d, &["add", "-A"]);
        sh(d, &["commit", "-qm", "init"]);
        t
    }

    fn input(cwd: &Path, command: &str) -> HookInput {
        HookInput {
            tool_name: Some("Bash".into()),
            tool_input: Some(ToolInput {
                command: Some(command.into()),
                ..ToolInput::default()
            }),
            cwd: Some(cwd.to_string_lossy().into_owned()),
        }
    }

    #[test]
    fn a_fresh_tie_passes() {
        let t = gen_repo();
        assert_eq!(block(&input(t.path(), "git commit -m x")), None);
    }

    #[test]
    fn a_staged_cargo_lock_without_regen_blocks() {
        let t = gen_repo();
        write(t.path(), "Cargo.lock", "lock-v2\n");
        sh(t.path(), &["add", "Cargo.lock"]);
        let (rule, msg) = block(&input(t.path(), "git commit -m bump")).expect("blocks");
        assert_eq!(rule, RULE);
        assert!(msg.contains("staged Cargo.lock"), "{msg}");
    }

    #[test]
    fn a_staged_manifest_change_blocks_and_names_it() {
        let t = gen_repo();
        write(t.path(), "crates/x/Cargo.toml", "[package]\nname = \"y\"\n");
        sh(t.path(), &["add", "-A"]);
        let (_, msg) = block(&input(t.path(), "cd x && git commit -m m")).expect("blocks");
        assert!(msg.contains("manifests: crates/x/Cargo.toml"), "{msg}");
    }

    #[test]
    fn a_worktree_only_change_passes_without_all_and_blocks_with_it() {
        let t = gen_repo();
        write(t.path(), "Cargo.lock", "lock-v2\n");
        assert_eq!(block(&input(t.path(), "git commit -m x")), None);
        assert!(block(&input(t.path(), "git commit -am x")).is_some());
        assert!(block(&input(t.path(), "git commit --all -m x")).is_some());
        assert_eq!(block(&input(t.path(), "git commit -m all")), None);
    }

    #[test]
    fn an_invalid_gen_lock_blocks() {
        let t = gen_repo();
        write(t.path(), GEN_LOCK, "{not json");
        sh(t.path(), &["add", GEN_LOCK]);
        let (_, msg) = block(&input(t.path(), "git commit -m x")).expect("blocks");
        assert!(msg.contains("not valid JSON"), "{msg}");
    }

    #[test]
    fn a_repo_without_a_gen_lock_passes() {
        let t = tempfile::tempdir().expect("tempdir");
        sh(t.path(), &["init", "-q"]);
        write(t.path(), "Cargo.lock", "x");
        sh(t.path(), &["add", "-A"]);
        assert_eq!(block(&input(t.path(), "git commit -m x")), None);
    }

    #[test]
    fn a_command_that_is_not_a_commit_passes() {
        let t = gen_repo();
        write(t.path(), "Cargo.lock", "lock-v2\n");
        sh(t.path(), &["add", "Cargo.lock"]);
        assert_eq!(block(&input(t.path(), "git status")), None);
        assert_eq!(block(&input(t.path(), "echo git commit")), None);
    }

    #[test]
    fn git_dash_c_resolves_the_repo_from_cwd() {
        let t = gen_repo();
        write(t.path(), "Cargo.lock", "lock-v2\n");
        sh(t.path(), &["add", "Cargo.lock"]);
        let parent = t.path().parent().expect("parent");
        let name = t.path().file_name().expect("name").to_string_lossy();
        let cmd = format!("git -C {name} commit -m x");
        assert!(block(&input(parent, &cmd)).is_some());
        assert_eq!(block(&input(parent, "git commit -m x")), None);
    }

    #[test]
    fn a_leading_cd_resolves_the_repo_away_from_the_session_cwd() {
        let t = gen_repo();
        write(t.path(), "Cargo.lock", "lock-v2\n");
        sh(t.path(), &["add", "Cargo.lock"]);
        let elsewhere = tempfile::tempdir().expect("tempdir");
        let abs = t.path().display();
        assert!(block(&input(elsewhere.path(), &format!("cd {abs} && git commit -qm x"))).is_some());
        assert!(block(&input(elsewhere.path(), &format!("cd '{abs}'; git add -A; git commit -m x"))).is_some());
        assert_eq!(block(&input(elsewhere.path(), "git commit -m x")), None);
    }

    #[test]
    fn combined_short_flags_are_read_up_to_the_value() {
        assert!(parse_commit("git commit -am x").expect("commit").all);
        assert!(parse_commit("git commit -qa").expect("commit").all);
        assert!(!parse_commit("git commit -ma").expect("commit").all);
        assert!(!parse_commit("git commit -m -a").expect("commit").all);
    }
}
