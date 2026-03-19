use std::process;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use guardrail::cache::{self, FsCache, FsFingerprinter};
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

fn resolve_all_rules() -> Result<Vec<Rule>> {
    let defaults = DefaultsProvider;
    let rules_d = DirectoryProvider { dir: config::rules_dir() };
    let user_config = config::load_user_config(&config::config_path())
        .context("loading guardrail config")?;
    let providers: Vec<&dyn RuleProvider> = vec![&defaults, &rules_d];
    config::resolve(&providers, &user_config).context("resolving rules")
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
        if item.context.downgrade_block() {
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
    let has_content_scan = scannable.iter().any(|s| s.context.downgrade_block());
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
fn emit_block(rule: &str, message: &str) -> ! {
    let response = serde_json::json!({
        "decision": "block",
        "reason": format!("guardrail [{rule}]: {message}")
    });
    println!("{response}");
    process::exit(1);
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
        let sev = match rule.severity {
            guardrail::Severity::Block => "BLOCK",
            guardrail::Severity::Warn => "WARN ",
        };
        eprintln!("[{sev}] {:<30} {}  {}", rule.name, rule.category, rule.message);
    }
    eprintln!("\n{} rules active", engine.rule_count());
    Ok(())
}
