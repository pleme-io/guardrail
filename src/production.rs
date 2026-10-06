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

use crate::cache::{self, FsCache, FsFingerprinter, HayaiError};
use crate::config::{self, DefaultsProvider, DirectoryProvider, RuleProvider};
use crate::engine::RegexEngine;
use crate::model::Rule;

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

/// The engine the hook runs — cached rule resolution, compiled RegexSet.
///
/// # Errors
/// Rule resolution or RegexSet compilation failure.
pub fn production_engine() -> Result<RegexEngine> {
    let rules = cache::resolve_cached(&fs_cache(), &fs_fingerprinter(), resolve_all_rules)?;
    RegexEngine::with_prefilter(rules, crate::engine::PrefixPrefilter::from_user_config())
        .context("compiling RegexSet")
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
}
