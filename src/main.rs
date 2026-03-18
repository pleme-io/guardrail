use std::process;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use guardrail::model::Decision;
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
    /// Validate the guardrail config file.
    Validate,
    /// List all active rules.
    List,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Check => cmd_check(),
        Command::Validate => cmd_validate(),
        Command::List => cmd_list(),
    }
}

fn build_engine() -> Result<RegexEngine> {
    use guardrail::config::{DefaultsProvider, DirectoryProvider, RuleProvider};

    let defaults = DefaultsProvider;
    let rules_d = DirectoryProvider { dir: config::rules_dir() };
    let user_config = config::load_user_config(&config::config_path())
        .context("loading guardrail config")?;

    let providers: Vec<&dyn RuleProvider> = vec![&defaults, &rules_d];
    let rules = config::resolve(&providers, &user_config)
        .context("resolving rules")?;
    RegexEngine::new(rules).context("compiling rules")
}

fn cmd_check() -> Result<()> {
    let input = hook::parse_stdin().context("reading hook input")?;
    let Some(command) = hook::extract_command(&input) else {
        // No command to check (not a Bash tool call) — allow
        return Ok(());
    };

    let engine = build_engine()?;
    match engine.check(command) {
        Decision::Allow => {
            // Exit 0, no output — allow
        }
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
            // Allow but warn — exit 0
        }
    }

    Ok(())
}

fn cmd_validate() -> Result<()> {
    let path = config::config_path();
    let user_config = config::load_user_config(&path)?;
    let defaults = config::default_rules();
    let rules = config::resolve_rules(&defaults, &user_config);
    let engine = RegexEngine::new(rules)?;
    eprintln!(
        "guardrail: config valid ({} rules active, {} disabled, {} extra)",
        engine.rule_count(),
        user_config.disabled_rules.len(),
        user_config.extra_rules.len(),
    );
    Ok(())
}

fn cmd_list() -> Result<()> {
    let defaults = config::default_rules();
    let user_config = config::load_user_config(&config::config_path())?;
    let rules = config::resolve_rules(&defaults, &user_config);
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
