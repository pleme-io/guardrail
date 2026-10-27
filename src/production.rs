//! The production rule set and engine — exactly what the `guardrail check`
//! hook enforces, as library functions.
//!
//! These lived in the CLI binary (`main.rs`), so an embedder — arnes gating
//! its Bash tool — would have had to copy them and could drift from the
//! rules the Claude Code hook applies. Now the CLI and every embedder build
//! the engine through the same functions: compiled-in defaults, the
//! operator's `rules.d/`, their `guardrail.yaml` overrides, and the same
//! fingerprinted cache.

use anyhow::{Context, Result};

use crate::cache::{self, CacheStore, FsCache, FsFingerprinter, HayaiError};
use crate::config::{self, DefaultsProvider, DirectoryProvider, RuleProvider};
use crate::engine::{LiteralIndex, ProductionNormalizer, RegexEngine};
use crate::model::Rule;
use crate::scope::ScopedRules;

/// The compiled-rules cache the hook uses.
#[must_use]
pub fn fs_cache() -> FsCache {
    FsCache {
        path: FsCache::default_path(),
    }
}

/// What invalidates that cache: the config file and the rules directory.
#[must_use]
pub fn fs_fingerprinter() -> FsFingerprinter {
    FsFingerprinter {
        config_path: config::config_path(),
        rules_dir: config::rules_dir(),
    }
}

/// Defaults + `rules.d/` + the user's `guardrail.yaml`, resolved.
///
/// # Errors
/// An unreadable config or rules directory, or a rule set that fails to resolve.
pub fn resolve_all_rules() -> Result<Vec<Rule>, HayaiError> {
    let defaults = DefaultsProvider;
    let rules_d = DirectoryProvider {
        dir: config::rules_dir(),
    };
    let user_config = config::load_user_config(&config::config_path())
        .context("loading guardrail config")
        .map_err(|e| HayaiError::Io {
            source: std::io::Error::other(e.to_string()),
        })?;
    let providers: Vec<&dyn RuleProvider> = vec![&defaults, &rules_d];
    config::resolve(&providers, &user_config)
        .context("resolving rules")
        .map_err(|e| HayaiError::Io {
            source: std::io::Error::other(e.to_string()),
        })
}

/// The resolved rules through the fingerprinted cache.
///
/// # Errors
/// Rule resolution failure.
pub fn production_rules() -> Result<Vec<Rule>> {
    Ok(cache::resolve_cached(
        &fs_cache(),
        &fs_fingerprinter(),
        resolve_all_rules,
    )?)
}

/// The `RegexSet` engine over the unscoped rules among `rules`.
///
/// # Errors
/// `RegexSet` compilation failure.
pub fn engine_for(rules: Vec<Rule>) -> Result<RegexEngine> {
    engine_through(&index_cache(), rules)
}

pub fn engine_through(
    store: &dyn CacheStore<LiteralIndex>,
    rules: Vec<Rule>,
) -> Result<RegexEngine> {
    let unscoped: Vec<Rule> = rules.into_iter().filter(|r| !r.is_scoped()).collect();
    let prefilter = crate::engine::PrefixPrefilter::from_user_config();
    let patterns = crate::engine::set_patterns(&unscoped);
    match LiteralIndex::through(store, &patterns) {
        Ok(index) => {
            RegexEngine::with_index(unscoped, index, ProductionNormalizer::default(), prefilter)
        }
        Err(_) => RegexEngine::with_prefilter(unscoped, prefilter),
    }
    .context("compiling RegexSet")
}

#[must_use]
pub fn index_cache() -> hayai::cache::FsCache {
    hayai::cache::FsCache::new(
        config::xdg_dir("XDG_CACHE_HOME", ".cache").join("guardrail/literal-index.json"),
    )
}

/// The engine the hook runs — cached rule resolution, compiled `RegexSet`,
/// over every rule that names no tool, field or cwd.
///
/// # Errors
/// Rule resolution or `RegexSet` compilation failure.
pub fn production_engine() -> Result<RegexEngine> {
    engine_for(production_rules()?)
}

/// Everything `check` matches against: the `RegexSet` engine and the scoped rules.
#[derive(Debug)]
pub struct Guard {
    pub engine: RegexEngine,
    pub scoped: ScopedRules,
}

impl Guard {
    /// # Errors
    /// `RegexSet` compilation failure. A scoped rule with an invalid regex is left out on its own.
    pub fn new(rules: Vec<Rule>) -> Result<Self> {
        let (scoped, _) = ScopedRules::new(&rules);
        Ok(Self {
            engine: engine_for(rules)?,
            scoped,
        })
    }

    #[must_use]
    pub fn rule(&self, name: &str) -> Option<&Rule> {
        use crate::RuleEngine;
        self.engine
            .rules()
            .iter()
            .find(|r| r.name == name)
            .or_else(|| self.scoped.rule(name))
    }
}

/// The guard the hook runs.
///
/// # Errors
/// Rule resolution or `RegexSet` compilation failure.
pub fn production_guard() -> Result<Guard> {
    Guard::new(production_rules()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuleEngine;
    use crate::model::Decision;

    #[test]
    fn the_production_engine_blocks_what_the_hook_blocks() {
        // Isolated from the operator's real config/cache.
        let dir = std::env::temp_dir().join(format!("guardrail-prod-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // SAFETY: test-scoped env override.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", dir.join("config"));
            std::env::set_var("XDG_CACHE_HOME", dir.join("cache"));
        }
        let engine = production_engine().unwrap();
        assert!(matches!(engine.check("rm -rf /"), Decision::Block { .. }));
        assert!(matches!(engine.check("rm -rf ./target"), Decision::Allow));
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn witnesses() -> Vec<String> {
        config::default_rules()
            .iter()
            .flat_map(|r| {
                [
                    crate::testing::derive_test_block(r),
                    crate::testing::derive_test_allow(r),
                ]
            })
            .chain(["ls -la".to_string(), "rm -rf /".to_string()])
            .collect()
    }

    fn verdicts(engine: &RegexEngine) -> Vec<String> {
        witnesses()
            .iter()
            .map(|w| engine.check(w).to_string())
            .collect()
    }

    fn reference() -> Vec<String> {
        let unscoped: Vec<Rule> = config::default_rules()
            .into_iter()
            .filter(|r| !r.is_scoped())
            .collect();
        let eager = hayai::RegexMatcher::with_plugins(
            unscoped.iter().map(|r| r.pattern.as_str()),
            ProductionNormalizer::default(),
            crate::engine::PrefixPrefilter::from_user_config(),
        )
        .unwrap();
        witnesses()
            .iter()
            .map(|w| {
                use hayai::MatchEngine;
                let hits = eager.check(w);
                let rule = hits
                    .iter()
                    .map(|&i| &unscoped[i])
                    .find(|r| r.severity == crate::model::Severity::Block)
                    .or_else(|| hits.first().map(|&i| &unscoped[i]));
                rule.map_or(Decision::Allow, Decision::from_rule)
                    .to_string()
            })
            .collect()
    }

    fn cache_in(dir: &tempfile::TempDir) -> hayai::cache::FsCache {
        hayai::cache::FsCache::new(dir.path().join("guardrail/literal-index.json"))
    }

    #[test]
    fn a_missing_index_is_built_written_and_agrees_with_the_eager_set() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = cache_in(&dir);
        let engine = engine_through(&store, config::default_rules()).unwrap();
        assert!(store.path.exists());
        assert_eq!(verdicts(&engine), reference());
        let warm = engine_through(&store, config::default_rules()).unwrap();
        assert_eq!(verdicts(&warm), reference());
    }

    #[test]
    fn a_corrupt_index_falls_back_to_a_correct_engine() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = cache_in(&dir);
        std::fs::create_dir_all(store.path.parent().unwrap()).unwrap();
        std::fs::write(&store.path, b"{\"fingerprint\": 1, \"data\": [garbage").unwrap();
        let engine = engine_through(&store, config::default_rules()).unwrap();
        assert_eq!(verdicts(&engine), reference());
        let reloaded: Option<(u64, LiteralIndex)> = store.load();
        assert!(reloaded.is_some());
    }

    #[test]
    fn a_stale_index_falls_back_to_a_correct_engine() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = cache_in(&dir);
        let stale = LiteralIndex::build(&["rm\\s+-rf"]).unwrap();
        store.save(stale.digest, &stale).unwrap();
        let engine = engine_through(&store, config::default_rules()).unwrap();
        assert_eq!(verdicts(&engine), reference());
    }

    #[test]
    fn an_index_that_lies_about_its_digest_is_rebuilt() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = cache_in(&dir);
        let rules = config::default_rules();
        let patterns: Vec<&str> = rules
            .iter()
            .filter(|r| !r.is_scoped())
            .map(|r| r.pattern.as_str())
            .collect();
        let mut lying = LiteralIndex::build(&patterns).unwrap();
        lying.entries.truncate(1);
        store.save(lying.digest, &lying).unwrap();
        let engine = engine_through(&store, rules).unwrap();
        assert_eq!(verdicts(&engine), reference());
    }

    #[test]
    fn an_unwritable_cache_still_gives_a_correct_engine() {
        let store = hayai::cache::FsCache::new("/dev/null/guardrail/literal-index.json");
        let engine = engine_through(&store, config::default_rules()).unwrap();
        assert_eq!(verdicts(&engine), reference());
    }

    #[test]
    fn an_invalid_rule_still_fails_closed_to_an_error() {
        let dir = tempfile::TempDir::new().unwrap();
        let rules = vec![Rule::builder("bad", "[invalid").build()];
        assert!(engine_through(&cache_in(&dir), rules).is_err());
    }
}
