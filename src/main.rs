use std::process;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use guardrail::cache::{self, FsCache, FsFingerprinter, HayaiError};
use guardrail::{CacheStore, Fingerprinter};
use guardrail::config::{self, DefaultsProvider, DirectoryProvider, RuleProvider};
use guardrail::hook::ScanContext;
use guardrail::journal::{self, WriteJournal};
use guardrail::model::{Decision, Rule};
use guardrail::{engine::RegexEngine, hook, RuleEngine};

#[derive(Parser)]
#[command(name = "guardrail", about = "Defensive guardrails for AI coding agents")]
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
    /// PostToolUse advice for Grep|Glob: nudge toward `mcp__zoekt__search`.
    SearchAdvise,
    /// PreToolUse nudge for Grep|Glob (advisory-only; never denies — yet).
    SearchNudge,
}

fn fs_cache() -> FsCache {
    FsCache { path: FsCache::default_path() }
}

fn fs_fingerprinter() -> FsFingerprinter {
    FsFingerprinter {
        config_path: config::config_path(),
        rules_dir: config::rules_dir(),
    }
}

fn resolve_all_rules() -> Result<Vec<Rule>, HayaiError> {
    let defaults = DefaultsProvider;
    let rules_d = DirectoryProvider { dir: config::rules_dir() };
    let user_config = config::load_user_config(&config::config_path())
        .context("loading guardrail config")
        .map_err(|e| HayaiError::Io { source: std::io::Error::new(std::io::ErrorKind::Other, e.to_string()) })?;
    let providers: Vec<&dyn RuleProvider> = vec![&defaults, &rules_d];
    config::resolve(&providers, &user_config)
        .context("resolving rules")
        .map_err(|e| HayaiError::Io { source: std::io::Error::new(std::io::ErrorKind::Other, e.to_string()) })
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
    let Some(fp) = input.tool_input.as_ref().and_then(|ti| ti.file_path.as_deref()) else {
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
// Search-leverage nudge — steer Grep|Glob toward mcp__zoekt__search
// ═══════════════════════════════════════════════════════════════════
//
// pleme-io repos are trigram-indexed by a warm zoekt daemon. A Grep/Glob
// over an indexed repo scans + reads whole files (~20–100K tokens) where a
// pre-indexed `mcp__zoekt__search` lookup answers the same question for ~50.
// These two subcommands ride the Grep|Glob hook matchers wired in
// blackmatter-claude and nudge the agent toward the index at the decision
// point. Both are ADVISORY-FIRST — neither ever blocks or errors the tool
// call (always exit 0; a parse failure emits nothing).

/// The Grep/Glob → zoekt redirect message, shared by both hooks.
const SEARCH_NUDGE_MSG: &str = "That Grep/Glob ran over an indexed repo — mcp__zoekt__search (sym:Name / file:pat lang:X / regex) is a pre-indexed lookup (~50 tokens) vs scanning + reading whole files (~20–100K). Next time search first, then Read only the exact range it points to.";

/// Whether a hook payload's tool is one this nudge applies to.
///
/// The `Grep|Glob` matcher in the hook wiring already scopes invocation, but
/// staying defensive means a mis-wired matcher can never spam unrelated tools.
fn is_search_tool(tool_name: Option<&str>) -> bool {
    matches!(tool_name, Some("Grep" | "Glob"))
}

/// `PostToolUse` hook for Grep|Glob. Emits advisory context (modern hook JSON)
/// nudging toward `mcp__zoekt__search`, then exits 0.
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
// mcp__zoekt__search. The Grep/Glob fields captured on ToolInput
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

    eprintln!("guardrail: compiled {} rules -> {}", engine.rule_count(), store.path.display());
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
        let sev = if rule.severity.is_blocking() { "BLOCK" } else { "WARN " };
        eprintln!("[{sev}] {:<30} {}  {}", rule.name, rule.category, rule.message);
    }
    eprintln!("\n{} rules active", engine.rule_count());
    Ok(())
}
