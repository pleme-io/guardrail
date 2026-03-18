use std::process;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use guardrail::cache::{self, CacheStore, FsCache, FsFingerprinter, Fingerprinter};
use guardrail::config::{self, DefaultsProvider, DirectoryProvider, RuleProvider};
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

    let store = fs_cache();
    store.save(&cache::CompiledCache {
        fingerprint: fs_fingerprinter().fingerprint(),
        rules,
    })?;

    eprintln!("guardrail: compiled {} rules → {}", engine.rule_count(), store.path.display());
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
