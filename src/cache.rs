use std::path::{Path, PathBuf};
use std::{env, fs};

use crate::model::Rule;

/// Cached compiled rules format.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CompiledCache {
    pub fingerprint: u64,
    pub rules: Vec<Rule>,
}

/// Trait for cache storage — abstracts filesystem for testability.
pub trait CacheStore {
    fn load(&self) -> Option<CompiledCache>;
    fn save(&self, cache: &CompiledCache) -> anyhow::Result<()>;
}

/// Trait for fingerprinting — abstracts filesystem stat calls.
pub trait Fingerprinter {
    fn fingerprint(&self) -> u64;
}

// ═══════════════════════════════════════════════════════════════════
// Filesystem implementations
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

impl CacheStore for FsCache {
    fn load(&self) -> Option<CompiledCache> {
        let content = fs::read(&self.path).ok()?;
        serde_json::from_slice(&content).ok()
    }

    fn save(&self, cache: &CompiledCache) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.path, serde_json::to_vec(cache)?)?;
        Ok(())
    }
}

/// Fingerprint based on file mtimes in config + rules.d/.
pub struct FsFingerprinter {
    pub config_path: PathBuf,
    pub rules_dir: PathBuf,
}

impl Fingerprinter for FsFingerprinter {
    fn fingerprint(&self) -> u64 {
        let mut hash: u64 = 0;
        if let Ok(meta) = fs::metadata(&self.config_path) {
            if let Ok(mtime) = meta.modified() {
                hash ^= mtime_nanos(mtime);
            }
        }
        if let Ok(entries) = fs::read_dir(&self.rules_dir) {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    if let Ok(mtime) = meta.modified() {
                        hash ^= mtime_nanos(mtime);
                    }
                }
            }
        }
        hash
    }
}

fn mtime_nanos(t: std::time::SystemTime) -> u64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

// ═══════════════════════════════════════════════════════════════════
// In-memory implementations (for testing)
// ═══════════════════════════════════════════════════════════════════

/// In-memory cache for testing.
pub struct MemCache {
    pub data: std::cell::RefCell<Option<CompiledCache>>,
}

impl MemCache {
    #[must_use]
    pub fn empty() -> Self {
        Self { data: std::cell::RefCell::new(None) }
    }
}

impl CacheStore for MemCache {
    fn load(&self) -> Option<CompiledCache> {
        self.data.borrow().as_ref().map(|c| CompiledCache {
            fingerprint: c.fingerprint,
            rules: c.rules.clone(),
        })
    }

    fn save(&self, cache: &CompiledCache) -> anyhow::Result<()> {
        *self.data.borrow_mut() = Some(CompiledCache {
            fingerprint: cache.fingerprint,
            rules: cache.rules.clone(),
        });
        Ok(())
    }
}

/// Fixed fingerprint for testing.
pub struct FixedFingerprinter(pub u64);

impl Fingerprinter for FixedFingerprinter {
    fn fingerprint(&self) -> u64 {
        self.0
    }
}

// ═══════════════════════════════════════════════════════════════════
// Resolver: cache-aware rule resolution
// ═══════════════════════════════════════════════════════════════════

/// Resolve rules with caching. Try cache first, fall back to provider
/// resolution, auto-populate cache on miss.
pub fn resolve_cached(
    cache: &dyn CacheStore,
    fp: &dyn Fingerprinter,
    resolve_fn: impl FnOnce() -> anyhow::Result<Vec<Rule>>,
) -> anyhow::Result<Vec<Rule>> {
    let current_fp = fp.fingerprint();

    // Cache hit
    if let Some(cached) = cache.load() {
        if cached.fingerprint == current_fp {
            return Ok(cached.rules);
        }
    }

    // Cache miss — resolve and save
    let rules = resolve_fn()?;
    let _ = cache.save(&CompiledCache {
        fingerprint: current_fp,
        rules: rules.clone(),
    });
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Category, Severity};

    fn test_rules() -> Vec<Rule> {
        vec![Rule {
            name: "test".into(),
            pattern: "test".into(),
            severity: Severity::Block,
            message: "test".into(),
            category: Category::Filesystem,
        }]
    }

    #[test]
    fn cache_miss_resolves_and_saves() {
        let cache = MemCache::empty();
        let fp = FixedFingerprinter(42);
        let rules = resolve_cached(&cache, &fp, || Ok(test_rules())).unwrap();
        assert_eq!(rules.len(), 1);
        // Cache should now be populated
        assert!(cache.load().is_some());
        assert_eq!(cache.load().unwrap().fingerprint, 42);
    }

    #[test]
    fn cache_hit_skips_resolution() {
        let cache = MemCache::empty();
        let fp = FixedFingerprinter(42);
        // Populate cache
        cache.save(&CompiledCache { fingerprint: 42, rules: test_rules() }).unwrap();
        // Resolve should use cache (closure should NOT be called)
        let rules = resolve_cached(&cache, &fp, || {
            panic!("should not be called on cache hit");
        }).unwrap();
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn stale_cache_resolves_fresh() {
        let cache = MemCache::empty();
        let fp = FixedFingerprinter(99); // different from cached
        cache.save(&CompiledCache { fingerprint: 42, rules: vec![] }).unwrap();
        let rules = resolve_cached(&cache, &fp, || Ok(test_rules())).unwrap();
        assert_eq!(rules.len(), 1);
        // Cache should be updated
        assert_eq!(cache.load().unwrap().fingerprint, 99);
    }

    #[test]
    fn mem_cache_empty_returns_none() {
        let cache = MemCache::empty();
        assert!(cache.load().is_none());
    }

    #[test]
    fn fixed_fingerprinter() {
        let fp = FixedFingerprinter(12345);
        assert_eq!(fp.fingerprint(), 12345);
    }
}
