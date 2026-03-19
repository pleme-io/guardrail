use std::path::PathBuf;
use std::{env, fs};

// Re-export hayai cache types
pub use hayai::cache::{CacheStore, FixedFingerprinter, Fingerprinter, MemCache, resolve_cached};

use crate::model::Rule;

/// Backward-compatible type alias for cached compiled rules.
pub type CompiledCache = Vec<Rule>;

// ═══════════════════════════════════════════════════════════════════
// Filesystem implementations (guardrail-specific)
// ═══════════════════════════════════════════════════════════════════

/// Cache stored at `~/.cache/guardrail/compiled.json`.
pub struct FsCache {
    pub path: PathBuf,
}

impl FsCache {
    #[must_use]
    pub fn default_path() -> PathBuf {
        env::var("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                PathBuf::from(env::var("HOME").unwrap_or_default()).join(".cache")
            })
            .join("guardrail/compiled.json")
    }
}

impl CacheStore<Vec<Rule>> for FsCache {
    fn load(&self) -> Option<(u64, Vec<Rule>)> {
        let content = fs::read(&self.path).ok()?;
        let entry: FsCacheEntry = serde_json::from_slice(&content).ok()?;
        Some((entry.fingerprint, entry.rules))
    }

    fn save(&self, fingerprint: u64, data: &Vec<Rule>) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let entry = FsCacheEntry {
            fingerprint,
            rules: data.clone(),
        };
        fs::write(&self.path, serde_json::to_vec(&entry)?)?;
        Ok(())
    }
}

/// On-disk JSON format for backward compatibility with existing cache files.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct FsCacheEntry {
    fingerprint: u64,
    rules: Vec<Rule>,
}

/// Fingerprint based on file mtimes in config + rules.d/.
///
/// Delegates to hayai's `FsFingerprinter` internally.
pub struct FsFingerprinter {
    pub config_path: PathBuf,
    pub rules_dir: PathBuf,
}

impl Fingerprinter for FsFingerprinter {
    fn fingerprint(&self) -> u64 {
        let fp = hayai::cache::FsFingerprinter {
            paths: vec![self.config_path.clone(), self.rules_dir.clone()],
        };
        fp.fingerprint()
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Rule;

    fn test_rules() -> Vec<Rule> {
        vec![Rule::builder("test", "test").message("test").build()]
    }

    #[test]
    fn cache_miss_resolves_and_saves() {
        let cache: MemCache<Vec<Rule>> = MemCache::empty();
        let fp = FixedFingerprinter(42);
        let rules = resolve_cached(&cache, &fp, || Ok(test_rules())).unwrap();
        assert_eq!(rules.len(), 1);
        // Cache should now be populated
        assert!(cache.load().is_some());
        assert_eq!(cache.load().unwrap().0, 42);
    }

    #[test]
    fn cache_hit_skips_resolution() {
        let cache: MemCache<Vec<Rule>> = MemCache::empty();
        let fp = FixedFingerprinter(42);
        // Populate cache
        cache.save(42, &test_rules()).unwrap();
        // Resolve should use cache (closure should NOT be called)
        let rules = resolve_cached(&cache, &fp, || {
            panic!("should not be called on cache hit");
        }).unwrap();
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn stale_cache_resolves_fresh() {
        let cache: MemCache<Vec<Rule>> = MemCache::empty();
        let fp = FixedFingerprinter(99); // different from cached
        cache.save(42, &vec![]).unwrap();
        let rules = resolve_cached(&cache, &fp, || Ok(test_rules())).unwrap();
        assert_eq!(rules.len(), 1);
        // Cache should be updated
        assert_eq!(cache.load().unwrap().0, 99);
    }

    #[test]
    fn mem_cache_empty_returns_none() {
        let cache: MemCache<Vec<Rule>> = MemCache::empty();
        assert!(cache.load().is_none());
    }

    #[test]
    fn fixed_fingerprinter() {
        let fp = FixedFingerprinter(12345);
        assert_eq!(fp.fingerprint(), 12345);
    }
}
