use std::path::{Path, PathBuf};

use regex::Regex;

use crate::gitcall::{self, git_text};
use crate::hook::HookInput;
use crate::model::PrivateTerms;

pub const RULE: &str = "private-terms-gate";
const MAX_COMMITS: usize = 200;

#[derive(Debug)]
enum Matcher {
    Term(String),
    Pattern(Regex),
}

#[derive(Debug, Default)]
pub struct Terms {
    matchers: Vec<Matcher>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Hit {
    pub term: String,
    pub place: String,
}

fn bounded(line: &str, at: usize, len: usize) -> bool {
    let before = line[..at].chars().next_back();
    let after = line[at + len..].chars().next();
    !before.is_some_and(|c| c.is_ascii_alphanumeric())
        && !after.is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

impl Terms {
    #[must_use]
    pub fn load(cfg: &PrivateTerms) -> Self {
        let mut matchers: Vec<Matcher> = cfg.terms.iter().filter_map(|t| term(t)).collect();
        for file in &cfg.term_files {
            matchers.extend(read_term_file(&gitcall::expand_home(file)));
        }
        Self { matchers }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.matchers.is_empty()
    }

    #[must_use]
    pub fn find(&self, line: &str) -> Option<String> {
        let lower = line.to_ascii_lowercase();
        self.matchers.iter().find_map(|m| match m {
            Matcher::Term(t) => lower
                .match_indices(t.as_str())
                .any(|(at, _)| bounded(line, at, t.len()))
                .then(|| t.clone()),
            Matcher::Pattern(re) => re.find(line).map(|m| m.as_str().to_string()),
        })
    }
}

fn term(t: &str) -> Option<Matcher> {
    let t = t.trim().to_ascii_lowercase();
    (!t.is_empty()).then_some(Matcher::Term(t))
}

fn read_term_file(path: &Path) -> Vec<Matcher> {
    let Some(doc) = std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_norway::from_str::<serde_norway::Value>(&s).ok())
    else {
        return Vec::new();
    };
    let Some(entries) = doc
        .get("entries")
        .and_then(serde_norway::Value::as_sequence)
    else {
        return Vec::new();
    };
    entries
        .iter()
        .filter(|e| {
            e.get("scope")
                .and_then(serde_norway::Value::as_str)
                .is_none_or(|s| s == "never")
        })
        .filter_map(|e| {
            if let Some(t) = e.get("term").and_then(serde_norway::Value::as_str) {
                term(t)
            } else {
                e.get("pattern")
                    .and_then(serde_norway::Value::as_str)
                    .and_then(|p| Regex::new(p).ok())
                    .map(Matcher::Pattern)
            }
        })
        .collect()
}

#[must_use]
pub fn slug_of(url: &str) -> Option<String> {
    let url = url.trim().trim_end_matches('/');
    let url = url.strip_suffix(".git").unwrap_or(url);
    let path = if let Some((_, rest)) = url.split_once("://") {
        rest.split_once('/')?.1
    } else {
        url.rsplit_once(':')?.1
    };
    let mut parts = path.rsplitn(3, '/');
    let name = parts.next()?;
    let owner = parts.next()?;
    (!name.is_empty() && !owner.is_empty()).then(|| format!("{owner}/{name}").to_ascii_lowercase())
}

fn listed_public(file: &crate::model::VisibilityFile, slug: &str) -> bool {
    let Some((owner, name)) = slug.split_once('/') else {
        return false;
    };
    if !file.owner.eq_ignore_ascii_case(owner) {
        return false;
    }
    let Some(doc) = std::fs::read_to_string(gitcall::expand_home(&file.path))
        .ok()
        .and_then(|s| serde_norway::from_str::<serde_norway::Value>(&s).ok())
    else {
        return false;
    };
    let default = doc
        .get("repo_defaults")
        .and_then(|d| d.get("visibility"))
        .and_then(serde_norway::Value::as_str);
    doc.get("repos")
        .and_then(serde_norway::Value::as_sequence)
        .into_iter()
        .flatten()
        .filter(|r| {
            r.get("name")
                .and_then(serde_norway::Value::as_str)
                .is_some_and(|n| n.eq_ignore_ascii_case(name))
        })
        .any(|r| {
            r.get("visibility")
                .and_then(serde_norway::Value::as_str)
                .or(default)
                == Some("public")
        })
}

#[must_use]
pub fn public_slug(cfg: &PrivateTerms, top: &Path) -> Option<String> {
    let slug = slug_of(&git_text(top, &["remote", "get-url", "origin"])?)?;
    let public = cfg
        .public_repos
        .iter()
        .any(|r| r.eq_ignore_ascii_case(&slug))
        || cfg.visibility_files.iter().any(|f| listed_public(f, &slug));
    public.then_some(slug)
}

fn scan_diff(terms: &Terms, diff: &str, prefix: &str) -> Option<Hit> {
    let mut file = String::new();
    let mut line = 0usize;
    for l in diff.lines() {
        if let Some(path) = l.strip_prefix("+++ ") {
            file = path.strip_prefix("b/").unwrap_or(path).to_string();
        } else if let Some(hunk) = l.strip_prefix("@@ ") {
            line = hunk
                .split_whitespace()
                .find_map(|t| t.strip_prefix('+'))
                .and_then(|t| t.split(',').next())
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
        } else if let Some(added) = l.strip_prefix('+') {
            if let Some(term) = terms.find(added) {
                return Some(Hit {
                    term,
                    place: format!("{prefix}{file}:{line}"),
                });
            }
            line += 1;
        } else if l.starts_with(' ') {
            line += 1;
        }
    }
    None
}

fn scan_text(terms: &Terms, text: &str, place: &str) -> Option<Hit> {
    text.lines().enumerate().find_map(|(i, l)| {
        terms.find(l).map(|term| Hit {
            term,
            place: format!("{place}:{}", i + 1),
        })
    })
}

const DIFF: [&str; 4] = ["-U0", "--no-color", "--no-ext-diff", "--no-renames"];

fn commit_hit(terms: &Terms, top: &Path, call: &crate::genlock::CommitCall) -> Option<Hit> {
    if let Some(hit) = scan_text(terms, &call.call.args, "the commit message") {
        return Some(hit);
    }
    let mut args = vec!["diff"];
    args.push(if call.all { "HEAD" } else { "--cached" });
    args.extend(DIFF);
    scan_diff(terms, &git_text(top, &args)?, "")
}

fn push_source(args: &str) -> Option<String> {
    let positional: Vec<&str> = args
        .split_whitespace()
        .filter(|t| !t.starts_with('-'))
        .collect();
    let src = positional
        .get(1)?
        .trim_start_matches('+')
        .split(':')
        .next()?;
    (!src.is_empty()).then(|| gitcall::unquote(src).to_string())
}

fn push_hit(terms: &Terms, top: &Path, args: &str) -> Option<Hit> {
    let tip = push_source(args)
        .filter(|s| {
            git_text(
                top,
                &[
                    "rev-parse",
                    "--verify",
                    "--quiet",
                    &format!("{s}^{{commit}}"),
                ],
            )
            .is_some()
        })
        .unwrap_or_else(|| "HEAD".to_string());
    let commits = git_text(top, &["rev-list", &tip, "--not", "--remotes"])?;
    for c in commits.lines().take(MAX_COMMITS) {
        let short = &c[..c.len().min(12)];
        let message = git_text(top, &["log", "-1", "--format=%B", c])?;
        if let Some(hit) = scan_text(terms, &message, &format!("commit {short} message")) {
            return Some(hit);
        }
        let mut args = vec!["show", "--format="];
        args.extend(DIFF);
        args.push(c);
        if let Some(hit) = scan_diff(terms, &git_text(top, &args)?, &format!("commit {short} ")) {
            return Some(hit);
        }
    }
    None
}

fn existing_dir(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .skip(1)
        .find(|p| p.is_dir())
        .map(Path::to_path_buf)
}

fn write_hit(terms: &Terms, cfg: &PrivateTerms, input: &HookInput) -> Option<(String, Hit)> {
    let ti = input.tool_input.as_ref()?;
    let path = PathBuf::from(ti.file_path.as_deref()?);
    let path = if path.is_absolute() {
        path
    } else {
        PathBuf::from(input.cwd.as_deref()?).join(path)
    };
    let text = ti
        .content
        .as_deref()
        .or(ti.new_string.as_deref())
        .or(ti.new_source.as_deref())?;
    let top = gitcall::toplevel(&existing_dir(&path)?)?;
    let slug = public_slug(cfg, &top)?;
    let rel = path
        .strip_prefix(&top)
        .unwrap_or(&path)
        .display()
        .to_string();
    Some((slug, scan_text(terms, text, &rel)?))
}

fn git_hit(terms: &Terms, cfg: &PrivateTerms, input: &HookInput) -> Option<(String, Hit)> {
    let command = input.tool_input.as_ref()?.command.as_deref()?;
    let cwd = input.cwd.as_deref();
    if let Some(call) = crate::genlock::parse_commit(command) {
        let top = gitcall::toplevel(&gitcall::dir(cwd, &call.call))?;
        let slug = public_slug(cfg, &top)?;
        return Some((slug, commit_hit(terms, &top, &call)?));
    }
    let call = gitcall::parse(command, "push")?;
    let top = gitcall::toplevel(&gitcall::dir(cwd, &call))?;
    let slug = public_slug(cfg, &top)?;
    Some((slug, push_hit(terms, &top, &call.args)?))
}

#[must_use]
pub fn block(cfg: &PrivateTerms, input: &HookInput) -> Option<(String, String)> {
    if !cfg.enable {
        return None;
    }
    let terms = Terms::load(cfg);
    if terms.is_empty() {
        return None;
    }
    let (slug, hit) = match input.tool_name.as_deref() {
        Some("Bash") | None => git_hit(&terms, cfg, input)?,
        _ => write_hit(&terms, cfg, input)?,
    };
    Some((
        RULE.to_string(),
        format!(
            "private term `{}` at {} would land in the public repo {slug}: genericize it or move it to a private repo, and keep it out of commit messages too",
            hit.term, hit.place
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gitcall::fixture::{sh, write};
    use crate::hook::ToolInput;
    use crate::model::VisibilityFile;

    const PUBLIC: &str = "git@github.com:acme/widget.git";
    const PRIVATE: &str = "https://github.com/acme/vault.git";

    fn cfg() -> PrivateTerms {
        PrivateTerms {
            terms: vec!["tenant-a".into(), "acmeServices".into(), "zorbank".into()],
            public_repos: vec!["acme/widget".into()],
            ..PrivateTerms::default()
        }
    }

    fn repo(origin: &str) -> tempfile::TempDir {
        let t = tempfile::tempdir().expect("tempdir");
        let d = t.path();
        sh(d, &["init", "-q", "-b", "main"]);
        sh(d, &["remote", "add", "origin", origin]);
        write(d, "README.md", "hello\n");
        sh(d, &["add", "-A"]);
        sh(d, &["commit", "-qm", "init"]);
        sh(d, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
        t
    }

    fn bash(cwd: &Path, command: &str) -> HookInput {
        HookInput {
            tool_name: Some("Bash".into()),
            tool_input: Some(ToolInput {
                command: Some(command.into()),
                ..ToolInput::default()
            }),
            cwd: Some(cwd.to_string_lossy().into_owned()),
        }
    }

    fn stage(t: &tempfile::TempDir, body: &str) {
        write(t.path(), "values.yaml", body);
        sh(t.path(), &["add", "-A"]);
    }

    #[test]
    fn a_term_staged_in_a_public_repo_blocks_and_names_file_and_line() {
        let t = repo(PUBLIC);
        stage(&t, "root:\n  name: x\nacmeServices:\n  a: 1\n");
        let (rule, msg) = block(&cfg(), &bash(t.path(), "git commit -m values")).expect("blocks");
        assert_eq!(rule, RULE);
        assert!(msg.contains("`acmeservices` at values.yaml:3"), "{msg}");
        assert!(msg.contains("acme/widget"), "{msg}");
    }

    #[test]
    fn the_same_change_in_a_private_repo_passes() {
        let t = repo(PRIVATE);
        stage(&t, "acmeServices: {}\n");
        assert_eq!(block(&cfg(), &bash(t.path(), "git commit -m x")), None);
    }

    #[test]
    fn a_clean_change_in_a_public_repo_passes() {
        let t = repo(PUBLIC);
        stage(&t, "services: {}\ntenant-ab: no\nretenant-a: no\n");
        assert_eq!(block(&cfg(), &bash(t.path(), "git commit -m x")), None);
    }

    #[test]
    fn removing_a_term_passes() {
        let t = repo(PUBLIC);
        write(t.path(), "values.yaml", "zorbank: 1\n");
        sh(t.path(), &["add", "-A"]);
        sh(t.path(), &["commit", "-qm", "seed"]);
        sh(
            t.path(),
            &["update-ref", "refs/remotes/origin/main", "HEAD"],
        );
        stage(&t, "generic: 1\n");
        assert_eq!(block(&cfg(), &bash(t.path(), "git commit -m scrub")), None);
    }

    #[test]
    fn a_read_failure_passes() {
        let t = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            block(&cfg(), &bash(t.path(), "git commit -m tenant-a")),
            None
        );
        let mut c = cfg();
        c.term_files = vec!["/nonexistent/terms.yaml".into()];
        c.terms.clear();
        let r = repo(PUBLIC);
        stage(&r, "tenant-a\n");
        assert_eq!(block(&c, &bash(r.path(), "git commit -m x")), None);
    }

    #[test]
    fn the_commit_message_is_scanned() {
        let t = repo(PUBLIC);
        stage(&t, "fine\n");
        assert!(block(&cfg(), &bash(t.path(), "git commit -m 'fix for tenant-a'")).is_some());
    }

    #[test]
    fn a_push_scans_every_unpushed_commit_and_its_message() {
        let t = repo(PUBLIC);
        stage(&t, "zorbank: 1\n");
        sh(t.path(), &["commit", "-qm", "add"]);
        stage(&t, "generic: 1\n");
        sh(t.path(), &["commit", "-qm", "later"]);
        let (_, msg) = block(&cfg(), &bash(t.path(), "git push origin main")).expect("blocks");
        assert!(
            msg.contains("`zorbank`") && msg.contains("values.yaml:1"),
            "{msg}"
        );

        let clean = repo(PUBLIC);
        stage(&clean, "generic\n");
        sh(clean.path(), &["commit", "-qm", "for tenant-a"]);
        let (_, msg) = block(&cfg(), &bash(clean.path(), "git push")).expect("blocks");
        assert!(msg.contains("message"), "{msg}");
    }

    #[test]
    fn a_push_with_nothing_new_passes() {
        let t = repo(PUBLIC);
        assert_eq!(block(&cfg(), &bash(t.path(), "git push")), None);
    }

    #[test]
    fn a_write_into_a_public_repo_blocks() {
        let t = repo(PUBLIC);
        let file = t.path().join("docs/x.md");
        let input = HookInput {
            tool_name: Some("Write".into()),
            tool_input: Some(ToolInput {
                file_path: Some(file.to_string_lossy().into_owned()),
                content: Some("ok\nsee tenant-a\n".into()),
                ..ToolInput::default()
            }),
            cwd: Some("/".into()),
        };
        let (_, msg) = block(&cfg(), &input).expect("blocks");
        assert!(msg.contains("docs/x.md:2"), "{msg}");
    }

    #[test]
    fn disabled_or_without_terms_it_never_runs() {
        let t = repo(PUBLIC);
        stage(&t, "tenant-a\n");
        let mut off = cfg();
        off.enable = false;
        assert_eq!(block(&off, &bash(t.path(), "git commit -m x")), None);
        let mut empty = cfg();
        empty.terms.clear();
        assert_eq!(block(&empty, &bash(t.path(), "git commit -m x")), None);
    }

    #[test]
    fn visibility_comes_from_a_posture_file_and_terms_from_a_denylist() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(
            dir.path(),
            "org.yaml",
            "repo_defaults:\n  visibility: private\nrepos:\n- name: widget\n  visibility: public\n- name: vault\n",
        );
        write(
            dir.path(),
            "deny.yaml",
            "entries:\n- term: zorbank\n  kind: x\n- term: acme\n  scope: vendor\n- pattern: '\\b10\\.9\\.[0-9]+\\.[0-9]+\\b'\n  kind: y\n",
        );
        let c = PrivateTerms {
            term_files: vec![dir.path().join("deny.yaml").display().to_string()],
            visibility_files: vec![VisibilityFile {
                path: dir.path().join("org.yaml").display().to_string(),
                owner: "acme".into(),
            }],
            ..PrivateTerms::default()
        };
        let public = repo(PUBLIC);
        stage(&public, "acme widget\n");
        assert_eq!(block(&c, &bash(public.path(), "git commit -m x")), None);
        stage(&public, "host 10.9.1.2\n");
        assert!(block(&c, &bash(public.path(), "git commit -m x")).is_some());
        let private = repo(PRIVATE);
        stage(&private, "zorbank\n");
        assert_eq!(block(&c, &bash(private.path(), "git commit -m x")), None);
    }

    #[test]
    fn slugs_parse_from_ssh_and_https() {
        assert_eq!(slug_of(PUBLIC).as_deref(), Some("acme/widget"));
        assert_eq!(slug_of(PRIVATE).as_deref(), Some("acme/vault"));
        assert_eq!(
            slug_of("ssh://git@host:22/Acme/W/").as_deref(),
            Some("acme/w")
        );
        assert_eq!(slug_of("nowhere"), None);
    }

    #[test]
    fn terms_bound_on_alphanumerics_but_match_camel_case_joins() {
        let terms = Terms::load(&cfg());
        assert!(terms.find("x: zorbank").is_some());
        assert!(terms.find("zorbankStaging").is_some());
        assert!(terms.find("ZORBANK_X").is_some());
        assert!(terms.find("zorbanks").is_none());
        assert!(terms.find("myzorbank").is_none());
    }
}
