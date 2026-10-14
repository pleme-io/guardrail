use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;

use regex::Regex;

static CD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[;&|(]\s*)(?:cd|pushd)\s+([^\s;&|)]+)").expect("valid regex")
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitCall {
    pub cds: Vec<String>,
    pub dirs: Vec<String>,
    pub args: String,
}

#[must_use]
pub fn unquote(s: &str) -> &str {
    s.trim_matches(|c| c == '"' || c == '\'')
}

#[must_use]
pub fn expand_home(path: &str) -> PathBuf {
    match (path.strip_prefix('~'), std::env::var_os("HOME")) {
        (Some(rest), Some(home)) => PathBuf::from(home).join(rest.trim_start_matches('/')),
        _ => PathBuf::from(path),
    }
}

#[must_use]
pub fn parse(command: &str, sub: &str) -> Option<GitCall> {
    let re = Regex::new(&format!(
        r"(?:^|[;&|(]\s*)git((?:\s+-C\s+\S+)*)\s+{}\b([^;&|)]*)",
        regex::escape(sub)
    ))
    .ok()?;
    let caps = re.captures(command)?;
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
    Some(GitCall {
        cds,
        dirs,
        args: caps[2].to_string(),
    })
}

#[must_use]
pub fn dir(cwd: Option<&str>, call: &GitCall) -> PathBuf {
    let mut dir = PathBuf::from(cwd.unwrap_or("."));
    for d in &call.cds {
        let next = dir.join(expand_home(d));
        if next.is_dir() {
            dir = next;
        }
    }
    for d in &call.dirs {
        dir = dir.join(d);
    }
    dir
}

#[must_use]
pub fn git(dir: &Path, args: &[&str]) -> Option<Vec<u8>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    out.status.success().then_some(out.stdout)
}

#[must_use]
pub fn git_text(dir: &Path, args: &[&str]) -> Option<String> {
    git(dir, args).map(|b| String::from_utf8_lossy(&b).trim().to_string())
}

#[must_use]
pub fn toplevel(dir: &Path) -> Option<PathBuf> {
    git_text(dir, &["rev-parse", "--show-toplevel"])
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

#[cfg(test)]
pub mod fixture {
    use std::path::Path;
    use std::process::Command;

    pub fn sh(dir: &Path, args: &[&str]) {
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

    pub fn write(dir: &Path, path: &str, body: &str) {
        let p = dir.join(path);
        std::fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
        std::fs::write(p, body).expect("write");
    }
}
