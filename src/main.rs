use std::process;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use guardrail::cache::{self, FsCache, FsFingerprinter, HayaiError};
use guardrail::config::{self, DefaultsProvider, DirectoryProvider, RuleProvider};
use guardrail::hook::ScanContext;
use guardrail::journal::{self, WriteJournal};
use guardrail::model::{Decision, Rule};
use guardrail::{CacheStore, Fingerprinter};
use guardrail::{RuleEngine, engine::RegexEngine, hook};

#[derive(Parser)]
#[command(
    name = "guardrail",
    about = "Defensive guardrails for AI coding agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check a command from Claude Code hook JSON on stdin.
    Check,
    /// Pre-compile rules to cache for fast loading.
    Compile,
    /// Validate the guardrail config file.
    Validate,
    /// List all active rules.
    List,
    /// PostToolUse advice for Grep|Glob: nudge toward the codesearch index.
    SearchAdvise,
    /// PreToolUse nudge for Grep|Glob (advisory-only; never denies — yet).
    SearchNudge,
    /// PostToolUse advice for Bash|Write: a new primitive is being MINTED,
    /// so route the name through /naming before it sets.
    MintAdvise,
}

fn fs_cache() -> FsCache {
    FsCache {
        path: FsCache::default_path(),
    }
}

fn fs_fingerprinter() -> FsFingerprinter {
    FsFingerprinter {
        config_path: config::config_path(),
        rules_dir: config::rules_dir(),
    }
}

fn resolve_all_rules() -> Result<Vec<Rule>, HayaiError> {
    let defaults = DefaultsProvider;
    let rules_d = DirectoryProvider {
        dir: config::rules_dir(),
    };
    let user_config = config::load_user_config(&config::config_path())
        .context("loading guardrail config")
        .map_err(|e| HayaiError::Io {
            source: std::io::Error::new(std::io::ErrorKind::Other, e.to_string()),
        })?;
    let providers: Vec<&dyn RuleProvider> = vec![&defaults, &rules_d];
    config::resolve(&providers, &user_config)
        .context("resolving rules")
        .map_err(|e| HayaiError::Io {
            source: std::io::Error::new(std::io::ErrorKind::Other, e.to_string()),
        })
}

fn build_engine() -> Result<RegexEngine> {
    let rules = cache::resolve_cached(&fs_cache(), &fs_fingerprinter(), resolve_all_rules)?;
    RegexEngine::new(rules).context("compiling RegexSet")
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Check => cmd_check(),
        Command::Compile => cmd_compile(),
        Command::Validate => cmd_validate(),
        Command::List => cmd_list(),
        Command::SearchAdvise => cmd_search_advise(),
        Command::SearchNudge => cmd_search_nudge(),
        Command::MintAdvise => cmd_mint_advise(),
    }
}

// ═══════════════════════════════════════════════════════════════════
// Check command — multi-tool scanning
// ═══════════════════════════════════════════════════════════════════

fn cmd_check() -> Result<()> {
    let input = hook::parse_stdin().context("reading hook input")?;
    let scannable = hook::extract_scannable_content(&input);

    if scannable.is_empty() {
        return Ok(());
    }

    let engine = build_engine()?;
    let mut write_dangerous = false;

    for item in &scannable {
        if item.context.is_content() {
            write_dangerous |= check_content_item(&engine, &item.text);
        } else {
            check_command_item(&engine, item);
        }
    }

    record_write_journal(&input, &scannable, write_dangerous);
    Ok(())
}

/// Scan file content (Write/Edit/Notebook) line by line.
/// All matches downgraded to warn. Returns true if any dangerous line found.
fn check_content_item(engine: &RegexEngine, content: &str) -> bool {
    let mut dangerous = false;
    let lines = hook::scan_content_lines(content);
    for line in &lines {
        match engine.check(line) {
            Decision::Allow => {}
            Decision::Block { rule, message } | Decision::Warn { rule, message } => {
                dangerous = true;
                eprintln!("guardrail [{rule}]: {message}");
            }
            _ => {}
        }
    }
    dangerous
}

/// Scan a command (Bash/MCP). Enforces Block decisions.
fn check_command_item(engine: &RegexEngine, item: &hook::ScannableContent) {
    // Check Write→Bash chaining (lazy journal load)
    if item.context == ScanContext::BashCommand {
        check_journal_chain(&item.text);
    }

    match engine.check(&item.text) {
        Decision::Allow => {}
        Decision::Block { rule, message } => {
            emit_block(&rule, &message);
        }
        Decision::Warn { rule, message } => {
            eprintln!("guardrail [{rule}]: {message}");
        }
        _ => {}
    }
}

/// Check if a Bash command executes a recently-written dangerous file.
/// Only loads journal from disk when the command references script paths.
fn check_journal_chain(command: &str) {
    let executed_paths = journal::extract_executed_paths(command);
    if executed_paths.is_empty() {
        return;
    }
    let journal = WriteJournal::load();
    for path in &executed_paths {
        if journal.is_dangerous(path) {
            emit_block(
                "write-bash-chain",
                &format!("executing recently written dangerous file: {path}"),
            );
        }
    }
}

/// Record Write/Edit to journal if content was scanned.
fn record_write_journal(
    input: &hook::HookInput,
    scannable: &[hook::ScannableContent],
    dangerous: bool,
) {
    let has_content_scan = scannable.iter().any(|s| s.context.is_content());
    if !has_content_scan {
        return;
    }
    let Some(fp) = input
        .tool_input
        .as_ref()
        .and_then(|ti| ti.file_path.as_deref())
    else {
        return;
    };
    let mut journal = WriteJournal::load();
    journal.record(fp, dangerous);
    // Best-effort save — don't fail the check if journal write fails
    let _ = journal.save();
}

/// Emit a block decision JSON to stdout and exit with code 1.
///
/// On macOS with a TTY, prompts for Touch ID authentication first.
/// If the user authenticates successfully, the block is bypassed and
/// the command is allowed to proceed.
fn emit_block(rule: &str, message: &str) -> ! {
    // Attempt biometric bypass before blocking
    if guardrail::biometric::authenticate(rule, message) {
        // Authenticated — allow the command through
        process::exit(0);
    }

    let response = serde_json::json!({
        "decision": "block",
        "reason": format!("guardrail [{rule}]: {message}")
    });
    println!("{response}");
    process::exit(1);
}

// ═══════════════════════════════════════════════════════════════════
// Mint nudge — a new primitive is being born; route it through /naming
// ═══════════════════════════════════════════════════════════════════
//
// ── WHY THIS EXISTS (measured 2026-09-23)
//
// An agent scaffolded a new fleet tool — new directory under the org root,
// new Cargo.toml, new flake.nix — and named it with an ad-hoc `rg` sweep
// instead of `/naming`, even though the `naming` skill WAS deployed, its
// description already says it triggers when "minting any new crate / repo /
// doctrine / primitive", and a research pass in the same session had just
// told the agent "Canonical law: theory/NAMING.md. Procedure: the naming
// skill." Every advisory surface was correct and present; none of them fired
// at the moment the name was chosen.
//
// That is the whole argument for putting this in a HOOK rather than in more
// prose: the failure was not missing knowledge, it was knowledge that did not
// arrive at the decision point. A hook rides the tool call that mints the
// thing, which is exactly that point.
//
// ── WHAT COUNTS AS MINTING
//
// Creating a REPO ROOT under the org root — one path segment past
// `code/github/pleme-io` — or writing a repo-defining file into one. Work
// *inside* an existing repo is not minting and must stay silent, or the nudge
// becomes noise and gets ignored, which is how a gate dies.
//
// ADVISORY ONLY. It never blocks: naming is a judgement, and a hook that
// refuses to let you create a directory would be worse than the miss it is
// correcting.

/// The message injected when a mint is detected.
///
/// Names the three things the law actually requires, because "run /naming"
/// alone would send a reader to a procedure they then have to summarise. The
/// registration list is the part that gets skipped.
const MINT_NUDGE_MSG: &str = "That call is MINTING a new pleme-io primitive (a repo root under the org root, or a repo-defining file in one). Run /naming before the name sets: theory/NAMING.md Law 1 selects the language (Japanese for foundational substrate/tools/discipline, Brazilian-Portuguese for Tier-2+ places/flows/craft), Law 2 requires the literal gloss to teach the thing, Law 3 draws from a registered metaphor family. Law 4 is the one that keeps failing — sweep for collisions with `--no-ignore` (the org root is itself a git repo with `.gitignore = *`, so a bare rg reads ~6 files, not ~992 repos) and use a positive control to prove the sweep is not vacuously empty. Then register the name in theory/VOCABULARY.md, theory/NAMING.md's family table, repo-forge/repos.lisp, and pangea-architectures' org.yaml — a name that exists in only some of those is how a primitive gets minted by implication.";

/// The org root, as it appears in a path. Matched as a substring so `~`,
/// `$HOME` and an absolute `/Users/<who>` all hit.
const ORG_ROOT: &str = "code/github/pleme-io/";

/// A path under the org root, split at the repo boundary.
struct OrgPath<'a> {
    /// The path through the repo name — what `repo_has_commits` is asked about.
    root: &'a str,
    /// Whatever followed it; empty when the path IS a repo root.
    tail: &'a str,
}

/// Split `…/pleme-io/<repo>[/<tail>]`. `None` when the path is not under the
/// org root, or names the org root itself (which is not a repo being minted).
fn split_org_path(path: &str) -> Option<OrgPath<'_>> {
    let idx = path.find(ORG_ROOT)?;
    let after = idx + ORG_ROOT.len();
    let rest = path[after..].trim_end_matches('/');
    if rest.is_empty() {
        return None;
    }
    let repo_len = rest.find('/').unwrap_or(rest.len());
    Some(OrgPath {
        root: &path[..after + repo_len],
        tail: rest[repo_len..].trim_start_matches('/'),
    })
}

/// Does `path` name a REPO ROOT — exactly one segment past the org root —
/// rather than something inside an existing repo?
fn is_repo_root_path(path: &str) -> bool {
    split_org_path(path).is_some_and(|p| p.tail.is_empty())
}

/// The org root itself, which is where `cargo new <name>` is usually run from.
fn is_org_root_path(path: &str) -> bool {
    path.trim_end_matches('/').ends_with("code/github/pleme-io")
}

fn expand_home(path: &str) -> String {
    let Ok(home) = std::env::var("HOME") else {
        return path.to_string();
    };
    for prefix in ["~/", "$HOME/", "${HOME}/"] {
        if let Some(rest) = path.strip_prefix(prefix) {
            return format!("{home}/{rest}");
        }
    }
    path.to_string()
}

/// ★ The load-bearing false-positive defense: has this repo ever been
/// committed to?
///
/// A directory that exists but carries no commit is still being minted — the
/// name has not been registered anywhere and the nudge is exactly on time. A
/// repo WITH history has a name the fleet already knows, so `git init` in it,
/// `mkdir -p` on it, or a write to its `flake.nix` is ordinary work and must
/// stay silent. This one check retires four of the five classes below, and it
/// is only affordable because the hook is a Rust binary: a `stat` plus one
/// `read_dir` costs microseconds against a budget the reader never feels.
fn repo_has_commits(root: &str) -> bool {
    let dot_git = std::path::Path::new(&expand_home(root)).join(".git");
    match std::fs::metadata(&dot_git) {
        // A worktree or submodule links `.git` as a FILE, and only a repo that
        // already has history is ever linked that way.
        Ok(meta) if meta.is_file() => return true,
        Ok(_) => {}
        Err(_) => return false,
    }
    if dot_git.join("packed-refs").exists() {
        return true;
    }
    // `refs/heads` is empty between `git init` and the first commit — which is
    // precisely the window in which a name is still being chosen.
    std::fs::read_dir(dot_git.join("refs").join("heads"))
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false)
}

fn unquote(token: &str) -> &str {
    token.trim_matches('"').trim_matches('\'')
}

/// Which repo root, if any, a shell command is CREATING.
///
/// Scoped three ways, because a bare substring search over the whole command
/// fires on any mention of any repo: the verb must open its own segment (so a
/// quoted or echoed `mkdir` is inert), the path must be an argument of that
/// verb or the segment's `cd` target (so naming one repo while creating another
/// elsewhere is inert), and `git clone` anywhere marks the whole command as
/// adoption of an existing name rather than minting a new one.
fn minted_repo_root(cmd: &str) -> Option<String> {
    let segments: Vec<Vec<&str>> = cmd
        .split(['&', '|', ';', '\n'])
        .map(|segment| {
            let tokens: Vec<&str> = segment.split_whitespace().map(unquote).collect();
            // `sudo` is the one prefix that leaves the verb in command position.
            match tokens.first() {
                Some(&"sudo") => tokens[1..].to_vec(),
                _ => tokens,
            }
        })
        .collect();

    // Adoption, not minting: the name already exists upstream. Decided over
    // the WHOLE command, because `mkdir <dir> && git clone … <dir>` puts the
    // create verb first and the disqualifying clone second.
    if segments
        .iter()
        .any(|head| head.first() == Some(&"git") && head.get(1) == Some(&"clone"))
    {
        return None;
    }

    let mut cd_hint: Option<&str> = None;
    for head in &segments {
        let Some(&verb) = head.first() else { continue };

        if verb == "cd" {
            cd_hint = head.get(1).copied();
            continue;
        }

        let args: &[&str] = match (verb, head.get(1)) {
            ("mkdir", _) => &head[1..],
            ("git", Some(&"init")) | ("cargo", Some(&"new" | &"init")) => &head[2..],
            _ => continue,
        };
        let operands: Vec<&str> = args
            .iter()
            .copied()
            .filter(|t| !t.starts_with('-'))
            .collect();

        if let Some(path) = operands.iter().find(|p| is_repo_root_path(p)) {
            return Some((*path).to_string());
        }
        // `cd <org root> && cargo new <name>` — the name is bare, the place
        // comes from the segment before it.
        if let (Some(hint), Some(name)) = (cd_hint, operands.first()) {
            if is_org_root_path(hint) && !name.contains('/') {
                return Some(format!("{}/{name}", hint.trim_end_matches('/')));
            }
        }
        // `cd <repo root> && git init` — the verb carries no path of its own.
        if operands.is_empty() {
            if let Some(hint) = cd_hint.filter(|h| is_repo_root_path(h)) {
                return Some(hint.to_string());
            }
        }
    }
    None
}

/// Whether this tool call is minting a new primitive, given a way to ask
/// whether a repo is already established. Split out so tests state the
/// filesystem instead of building one.
fn is_minting_with(
    tool_name: Option<&str>,
    input: &hook::ToolInput,
    established: &dyn Fn(&str) -> bool,
) -> bool {
    let root: Option<String> = match tool_name {
        Some("Bash") => input.command.as_deref().and_then(minted_repo_root),
        // A repo-defining file mints even when the directory already exists —
        // but only while the repo has no history.
        Some("Write") => input
            .file_path
            .as_deref()
            .and_then(split_org_path)
            .filter(|split| matches!(split.tail, "Cargo.toml" | "flake.nix"))
            .map(|split| split.root.to_string()),
        _ => None,
    };
    root.is_some_and(|root| !established(&root))
}

/// Whether this tool call is minting a new primitive.
///
/// Deliberately narrow. A false positive on every `mkdir` would train the
/// reader to skip the message, and an ignored nudge is worth less than none.
fn is_minting(tool_name: Option<&str>, input: &hook::ToolInput) -> bool {
    is_minting_with(tool_name, input, &|root| repo_has_commits(root))
}

/// `PostToolUse` hook for Bash|Write. Emits the naming reminder when the call
/// minted something, and nothing otherwise. Always exits 0.
fn cmd_mint_advise() -> Result<()> {
    let Ok(input) = hook::parse_stdin() else {
        return Ok(());
    };
    let Some(tool_input) = &input.tool_input else {
        return Ok(());
    };
    if !is_minting(input.tool_name.as_deref(), tool_input) {
        return Ok(());
    }
    let response = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": MINT_NUDGE_MSG,
        }
    });
    println!("{response}");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════
// Search-leverage nudge — steer Grep|Glob toward the codesearch index
// ═══════════════════════════════════════════════════════════════════
//
// pleme-io repos are indexed by codesearch. A Grep/Glob over an indexed repo
// scans + reads whole files (~20–100K tokens) where a pre-indexed lookup
// answers the same question for ~50. These two subcommands ride the Grep|Glob
// hook matchers wired in blackmatter-claude and nudge the agent toward the
// index at the decision point. Both are ADVISORY-FIRST — neither ever blocks
// or errors the tool call (always exit 0; a parse failure emits nothing).
//
// ── WHY THIS NAMES codesearch AND NOT zoekt (corrected 2026-08-18)
//
// This message pointed at `mcp__zoekt__search` from its inception. **Zoekt was
// RETIRED fleet-wide on 2026-08-12** — all three surfaces (claude MCP, anvil
// MCP, the indexing daemon) are typed-flipped to `enable = false` and the
// generation carries zero zoekt store paths with its launchd jobs unloaded.
// So this hook spent its whole life after that date advising every agent, on
// every Grep and every Glob, to call into a dead plane: a nudge that costs a
// tool round-trip and returns either a hard failure or an answer off stale
// shards. That is worse than no nudge, because it is a *confident* wrong
// answer — the exact failure mode the retirement's own parity gate was built
// to avoid.
//
// The retirement was measured, not planned (`codesearch parity --gate` exits
// 0: corpus 1171/1171 zoekt repos, 0 missing; 15/15 capabilities served), and
// codesearch's EXACT plane is the direct replacement for what zoekt served.
// Two things the message must get right, because both are load-bearing:
//
//   * `search_exact` accepts zoekt-style filters in ONE query string
//     (`lang:rust case:yes fn\s+main`), so the operator's zoekt muscle memory
//     transfers. But `repo:`, `branch:`, `sym:` and `kind:` belong to OTHER
//     tools and are REFUSED with an error naming the right one rather than
//     silently ignored — so this message must not advertise `sym:`, which the
//     zoekt-era text did.
//   * `files_scanned: 0` means a broken walk or a near-empty resolved db, NOT
//     "no matches". Saying so here is what stops an agent reading a zero as
//     absence, which is the one way this nudge could cause a wrong conclusion.

/// The Grep/Glob → codesearch redirect message, shared by both hooks.
///
/// Names the three planes an agent actually needs and the one result that is
/// routinely misread. Kept to a single line: it is injected as
/// `additionalContext` on every Grep|Glob call, so its token cost is paid
/// hundreds of times a day.
const SEARCH_NUDGE_MSG: &str = "That Grep/Glob ran over an indexed repo — codesearch is a pre-indexed lookup (~50 tokens) vs scanning + reading whole files (~20–100K). Use mcp__codesearch__search_exact for regex/literal (it takes zoekt-style `lang:` / `file:` / `case:` filters in one query string), mcp__codesearch__semantic_search for intent, mcp__codesearch__search_repos to fan out across repos, mcp__codesearch__find_all_references for every call site. Then Read only the exact range it points to. Note `files_scanned: 0` means a broken walk or an empty resolved db — never read it as `no matches`.";

/// Whether a hook payload's tool is one this nudge applies to.
///
/// The `Grep|Glob` matcher in the hook wiring already scopes invocation, but
/// staying defensive means a mis-wired matcher can never spam unrelated tools.
fn is_search_tool(tool_name: Option<&str>) -> bool {
    matches!(tool_name, Some("Grep" | "Glob"))
}

/// `PostToolUse` hook for Grep|Glob. Emits advisory context (modern hook JSON)
/// nudging toward the codesearch index, then exits 0.
///
/// Never errors the tool call: a parse failure or a non-search tool emits
/// nothing and still exits 0.
fn cmd_search_advise() -> Result<()> {
    let Ok(input) = hook::parse_stdin() else {
        return Ok(());
    };
    if !is_search_tool(input.tool_name.as_deref()) {
        return Ok(());
    }
    let response = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": SEARCH_NUDGE_MSG,
        }
    });
    println!("{response}");
    Ok(())
}

/// `PreToolUse` hook for Grep|Glob. ADVISORY-ONLY for now: emits a no-op
/// `PreToolUse` payload (no `permissionDecision`) so the tool is never blocked.
///
// TODO(promote-to-deny): once false-positives confirmed low, gate on
// bare-identifier pattern (^[A-Za-z_][A-Za-z0-9_]*$) ∧ not single-file-scoped
// (no `path` narrowing a single file) ∧ index warm -> emit
// permissionDecision:"deny" with a redirect reason pointing at
// mcp__codesearch__search_exact. The Grep/Glob fields captured on ToolInput
// (pattern/path/glob/output_mode) exist precisely so this deny path is one
// edit away. Advisory-first is the deliberate design choice: prove the
// signal is high before ever blocking a tool call.
fn cmd_search_nudge() -> Result<()> {
    let Ok(input) = hook::parse_stdin() else {
        return Ok(());
    };
    if !is_search_tool(input.tool_name.as_deref()) {
        return Ok(());
    }
    // No-op PreToolUse payload — no permissionDecision, so nothing is blocked.
    let response = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse"
        }
    });
    println!("{response}");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════
// Other commands
// ═══════════════════════════════════════════════════════════════════

fn cmd_compile() -> Result<()> {
    let rules = resolve_all_rules()?;
    let engine = RegexEngine::new(rules.clone()).context("compiling RegexSet")?;

    let store = fs_cache();
    let fp = fs_fingerprinter().fingerprint();
    store.save(fp, &rules)?;

    eprintln!(
        "guardrail: compiled {} rules -> {}",
        engine.rule_count(),
        store.path.display()
    );
    Ok(())
}

fn cmd_validate() -> Result<()> {
    let engine = build_engine()?;
    let user_config = config::load_user_config(&config::config_path())?;
    eprintln!(
        "guardrail: config valid ({} rules active, {} disabled, {} extra)",
        engine.rule_count(),
        user_config.disabled_rules.len(),
        user_config.extra_rules.len(),
    );
    Ok(())
}

fn cmd_list() -> Result<()> {
    let engine = build_engine()?;
    for rule in engine.rules() {
        let sev = if rule.severity.is_blocking() {
            "BLOCK"
        } else {
            "WARN "
        };
        eprintln!(
            "[{sev}] {:<30} {}  {}",
            rule.name, rule.category, rule.message
        );
    }
    eprintln!("\n{} rules active", engine.rule_count());
    Ok(())
}

#[cfg(test)]
mod mint_tests {
    use super::*;

    fn bash(cmd: &str) -> hook::ToolInput {
        hook::ToolInput {
            command: Some(cmd.to_string()),
            ..Default::default()
        }
    }
    fn write(path: &str) -> hook::ToolInput {
        hook::ToolInput {
            file_path: Some(path.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn a_repo_root_is_one_segment_past_the_org_root() {
        assert!(is_repo_root_path("/Users/x/code/github/pleme-io/tsunagari"));
        assert!(is_repo_root_path("~/code/github/pleme-io/tsunagari/"));
        // Inside an existing repo is NOT minting — this is the false positive
        // that would make the nudge noise and get it ignored.
        assert!(!is_repo_root_path(
            "/Users/x/code/github/pleme-io/nix/modules/foo"
        ));
        assert!(!is_repo_root_path("/tmp/scratch/thing"));
        assert!(!is_repo_root_path("/Users/x/code/github/pleme-io/"));
    }

    #[test]
    fn creating_a_repo_root_mints() {
        assert!(
            is_minting(
                Some("Bash"),
                &bash("mkdir -p ~/code/github/pleme-io/tsunagari/src").clone()
            ) == false,
            "a path two deep is not a repo root"
        );
        assert!(is_minting(
            Some("Bash"),
            &bash("mkdir -p ~/code/github/pleme-io/tsunagari")
        ));
        assert!(is_minting(
            Some("Bash"),
            &bash("cd ~/code/github/pleme-io/tsunagari && git init -q")
        ));
    }

    #[test]
    fn ordinary_work_is_silent() {
        assert!(!is_minting(
            Some("Bash"),
            &bash("ls ~/code/github/pleme-io/nix")
        ));
        assert!(!is_minting(Some("Bash"), &bash("mkdir -p /tmp/scratch")));
        assert!(!is_minting(
            Some("Bash"),
            &bash("mkdir -p ~/code/github/pleme-io/nix/parts")
        ));
        assert!(!is_minting(
            Some("Grep"),
            &bash("mkdir -p ~/code/github/pleme-io/x")
        ));
    }

    #[test]
    fn a_repo_defining_file_mints_even_when_the_dir_exists() {
        assert!(is_minting(
            Some("Write"),
            &write("/Users/x/code/github/pleme-io/tsunagari/Cargo.toml")
        ));
        assert!(is_minting(
            Some("Write"),
            &write("/Users/x/code/github/pleme-io/tsunagari/flake.nix")
        ));
        // A Cargo.toml deeper in a workspace is ordinary work.
        assert!(!is_minting(
            Some("Write"),
            &write("/Users/x/code/github/pleme-io/nix/crates/a/Cargo.toml")
        ));
        assert!(!is_minting(
            Some("Write"),
            &write("/Users/x/code/github/pleme-io/tsunagari/src/main.rs")
        ));
    }

    // ── The false positives, one test per class ────────────────────────────
    //
    // Each of these fired on the first implementation. They are the reason the
    // detector asks the filesystem and scopes the path to the verb, rather
    // than searching the command for a substring.

    /// Pretend every repo named here is established (has commits).
    fn established(_root: &str) -> bool {
        true
    }
    /// Pretend nothing is established — a green field.
    fn fresh(_root: &str) -> bool {
        false
    }

    #[test]
    fn an_established_repo_is_never_minting() {
        // Re-initialising, re-mkdir-ing, or writing the flake of a repo that
        // already has history is ordinary work on a name the fleet knows.
        for cmd in [
            "cd ~/code/github/pleme-io/nix && git init",
            "mkdir -p ~/code/github/pleme-io/nix",
        ] {
            assert!(
                !is_minting_with(Some("Bash"), &bash(cmd), &established),
                "established repo should be silent: {cmd}"
            );
            assert!(
                is_minting_with(Some("Bash"), &bash(cmd), &fresh),
                "the same command on a repo with no commits SHOULD nudge: {cmd}"
            );
        }
        assert!(!is_minting_with(
            Some("Write"),
            &write("/Users/x/code/github/pleme-io/nix/flake.nix"),
            &established
        ));
    }

    #[test]
    fn a_repo_merely_mentioned_elsewhere_is_not_the_one_being_created() {
        // `mkdir` creates /tmp/x; the org path belongs to a `cp` in another
        // segment. The first implementation fired on this.
        assert!(!is_minting_with(
            Some("Bash"),
            &bash("mkdir -p /tmp/x && cp -r ~/code/github/pleme-io/nix /tmp/x"),
            &fresh
        ));
        assert!(!is_minting_with(
            Some("Bash"),
            &bash("mkdir -p /tmp/x; rm -rf ~/code/github/pleme-io/oldrepo"),
            &fresh
        ));
    }

    #[test]
    fn cloning_is_adoption_not_minting() {
        // `tend sync` shape: the name exists upstream already.
        assert!(!is_minting_with(
            Some("Bash"),
            &bash(
                "mkdir -p ~/code/github/pleme-io/foo && git clone \
                 git@github.com:pleme-io/foo ~/code/github/pleme-io/foo"
            ),
            &fresh
        ));
    }

    #[test]
    fn a_verb_that_is_not_in_command_position_is_inert() {
        // Quoted, echoed, or embedded in prose — not a creation.
        for cmd in [
            "echo \"mkdir ~/code/github/pleme-io/tsunagari\"",
            "git commit -m \"mkdir ~/code/github/pleme-io/tsunagari\"",
            "rg mkdir ~/code/github/pleme-io/tsunagari",
        ] {
            assert!(
                !is_minting_with(Some("Bash"), &bash(cmd), &fresh),
                "verb not in command position should be silent: {cmd}"
            );
        }
        // …but `sudo` still leaves it in command position.
        assert!(is_minting_with(
            Some("Bash"),
            &bash("sudo mkdir -p ~/code/github/pleme-io/tsunagari"),
            &fresh
        ));
    }

    #[test]
    fn a_bare_name_takes_its_place_from_the_cd() {
        // `cd <org root> && cargo new <name>` mints; the same from inside a
        // repo does not, because the name is then a workspace member.
        assert!(is_minting_with(
            Some("Bash"),
            &bash("cd ~/code/github/pleme-io && cargo new tsunagari"),
            &fresh
        ));
        assert!(!is_minting_with(
            Some("Bash"),
            &bash("cd ~/code/github/pleme-io/nix && cargo new helper"),
            &fresh
        ));
    }

    #[test]
    fn the_message_names_the_registration_surfaces() {
        // The registration list is the part that gets skipped, so it is the
        // part the message must carry.
        for surface in [
            "VOCABULARY.md",
            "repo-forge/repos.lisp",
            "org.yaml",
            "--no-ignore",
        ] {
            assert!(
                MINT_NUDGE_MSG.contains(surface),
                "message must name {surface}"
            );
        }
    }
}
