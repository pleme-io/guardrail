use std::path::PathBuf;
use std::process;
use std::{fs, io};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use guardrail::model::{Decision, Rule};
use guardrail::{config, engine::RegexEngine, hook, RuleEngine};

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
    /// Pre-compile rules to a cached binary for fast loading.
    Compile,
    /// Validate the guardrail config file.
    Validate,
    /// List all active rules.
    List,
}

/// Cache file path: ~/.cache/guardrail/compiled.json
fn cache_path() -> PathBuf {
    let cache_dir = std::env::var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".cache")
        })
        .join("guardrail");
    cache_dir.join("compiled.json")
}

/// Compute a freshness fingerprint from rules.d/ mtimes + config mtime.
fn rules_fingerprint() -> u64 {
    let mut hash: u64 = 0;
    let paths = [config::config_path()];
    for path in &paths {
        if let Ok(meta) = fs::metadata(path) {
            if let Ok(mtime) = meta.modified() {
                hash ^= mtime.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos() as u64;
            }
        }
    }
    let rules_dir = config::rules_dir();
    if let Ok(entries) = fs::read_dir(&rules_dir) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if let Ok(mtime) = meta.modified() {
                    hash ^= mtime.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos() as u64;
                }
            }
        }
    }
    hash
}

/// Cached compiled rules format.
#[derive(serde::Serialize, serde::Deserialize)]
struct CompiledCache {
    fingerprint: u64,
    rules: Vec<Rule>,
}

/// Try to load rules from cache. Returns None if cache is stale or missing.
fn load_cached_rules() -> Option<Vec<Rule>> {
    let path = cache_path();
    let content = fs::read(&path).ok()?;
    let cache: CompiledCache = serde_json::from_slice(&content).ok()?;
    if cache.fingerprint == rules_fingerprint() {
        Some(cache.rules)
    } else {
        None
    }
}

/// Resolve rules from all providers (full path — YAML parsing).
fn resolve_all_rules() -> Result<Vec<Rule>> {
    use guardrail::config::{DefaultsProvider, DirectoryProvider, RuleProvider};

    let defaults = DefaultsProvider;
    let rules_d = DirectoryProvider { dir: config::rules_dir() };
    let user_config = config::load_user_config(&config::config_path())
        .context("loading guardrail config")?;

    let providers: Vec<&dyn RuleProvider> = vec![&defaults, &rules_d];
    config::resolve(&providers, &user_config).context("resolving rules")
}

/// Build engine: try cache, auto-compile if stale, always fast.
fn build_engine() -> Result<RegexEngine> {
    let rules = if let Some(cached) = load_cached_rules() {
        cached
    } else {
        // Cache miss — resolve and compile for next time
        let resolved = resolve_all_rules()?;
        let _ = write_cache(&resolved); // best-effort, don't fail check
        resolved
    };
    RegexEngine::new(rules).context("compiling RegexSet")
}

/// Write rules to cache file.
fn write_cache(rules: &[Rule]) -> Result<()> {
    let cache = CompiledCache {
        fingerprint: rules_fingerprint(),
        rules: rules.to_vec(),
    };
    let path = cache_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, serde_json::to_vec(&cache)?)?;
    Ok(())
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

fn cmd_check() -> Result<()> {
    let input = hook::parse_stdin().context("reading hook input")?;
    let Some(command) = hook::extract_command(&input) else {
        return Ok(());
    };

    let engine = build_engine()?;
    match engine.check(command) {
        Decision::Allow => {}
        Decision::Block { rule, message } => {
            let response = serde_json::json!({
                "decision": "block",
                "reason": format!("guardrail [{rule}]: {message}")
            });
            println!("{response}");
            process::exit(1);
        }
        Decision::Warn { rule, message } => {
            eprintln!("guardrail [{rule}]: {message}");
        }
    }

    Ok(())
}

fn cmd_compile() -> Result<()> {
    let rules = resolve_all_rules()?;
    let engine = RegexEngine::new(rules.clone()).context("compiling RegexSet")?;

    let cache = CompiledCache {
        fingerprint: rules_fingerprint(),
        rules,
    };

    let path = cache_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_vec(&cache)?;
    fs::write(&path, &json)?;

    eprintln!(
        "guardrail: compiled {} rules → {} ({} bytes)",
        engine.rule_count(),
        path.display(),
        json.len()
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
    let rules = engine.rules();
    for rule in &rules {
        let sev = match rule.severity {
            guardrail::Severity::Block => "BLOCK",
            guardrail::Severity::Warn => "WARN ",
        };
        eprintln!("[{sev}] {:<30} {:?}  {}", rule.name, rule.category, rule.message);
    }
    eprintln!("\n{} rules active", rules.len());
    Ok(())
}
