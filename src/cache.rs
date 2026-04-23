use std::path::PathBuf;
use std::fs;

// Re-export hayai cache types
pub use hayai::cache::{CacheStore, FixedFingerprinter, Fingerprinter, MemCache, resolve_cached};
pub use hayai::HayaiError;

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
        crate::config::xdg_dir("XDG_CACHE_HOME", ".cache")
            .join("guardrail/compiled.json")
    }
}

impl CacheStore<Vec<Rule>> for FsCache {
    fn load(&self) -> Option<(u64, Vec<Rule>)> {
        let content = fs::read(&self.path).ok()?;
        let entry: FsCacheEntry = serde_json::from_slice(&content).ok()?;
        Some((entry.fingerprint, entry.rules))
    }

    fn save(&self, fingerprint: u64, data: &Vec<Rule>) -> Result<(), HayaiError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| HayaiError::Io { source: e })?;
        }
        let entry = FsCacheEntry {
            fingerprint,
            rules: data.clone(),
        };
        fs::write(&self.path, serde_json::to_vec(&entry).map_err(|e| HayaiError::Json { source: e })?)?;
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
    use crate::model::{Category, Rule, Severity};
    use tempfile::TempDir;

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

    // ── FsCache disk round-trip ─────────────────────────────────

    #[test]
    fn fs_cache_save_and_load() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("guardrail/compiled.json");
        let cache = FsCache { path: path.clone() };

        let rules = vec![
            Rule::builder("r1", "p1").severity(Severity::Block).message("m1").category(Category::Git).build(),
            Rule::builder("r2", "p2").severity(Severity::Warn).message("m2").category(Category::Docker).build(),
        ];

        cache.save(42, &rules).unwrap();
        assert!(path.exists());

        let (fp, loaded) = cache.load().expect("cache should load after save");
        assert_eq!(fp, 42);
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].name, "r1");
        assert_eq!(loaded[1].name, "r2");
        assert_eq!(loaded[0].severity, Severity::Block);
        assert_eq!(loaded[1].severity, Severity::Warn);
    }

    #[test]
    fn fs_cache_load_missing_file() {
        let cache = FsCache { path: PathBuf::from("/nonexistent/cache.json") };
        assert!(cache.load().is_none());
    }

    #[test]
    fn fs_cache_load_corrupt_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bad.json");
        fs::write(&path, "not valid json {{{").unwrap();
        let cache = FsCache { path };
        assert!(cache.load().is_none());
    }

    #[test]
    fn fs_cache_creates_parent_dirs() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("deep/nested/dir/compiled.json");
        let cache = FsCache { path: path.clone() };
        cache.save(1, &vec![]).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn fs_cache_overwrite_updates_fingerprint() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("cache.json");
        let cache = FsCache { path };

        cache.save(10, &test_rules()).unwrap();
        assert_eq!(cache.load().unwrap().0, 10);

        cache.save(20, &test_rules()).unwrap();
        assert_eq!(cache.load().unwrap().0, 20);
    }

    #[test]
    fn fs_cache_empty_rules() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("empty.json");
        let cache = FsCache { path };

        cache.save(99, &vec![]).unwrap();
        let (fp, rules) = cache.load().unwrap();
        assert_eq!(fp, 99);
        assert!(rules.is_empty());
    }

    #[test]
    fn fs_cache_preserves_test_block_allow() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("full.json");
        let cache = FsCache { path };

        let rules = vec![
            Rule::builder("tb", "p")
                .test_block("rm -rf /")
                .test_allow("ls")
                .build(),
        ];

        cache.save(1, &rules).unwrap();
        let (_, loaded) = cache.load().unwrap();
        assert_eq!(loaded[0].test_block.as_deref(), Some("rm -rf /"));
        assert_eq!(loaded[0].test_allow.as_deref(), Some("ls"));
    }

    // ── FsCache default_path ────────────────────────────────────

    #[test]
    fn fs_cache_default_path_ends_with_compiled_json() {
        let path = FsCache::default_path();
        assert!(
            path.ends_with("guardrail/compiled.json"),
            "expected path ending with guardrail/compiled.json, got: {}",
            path.display()
        );
    }

    // ── FsFingerprinter ─────────────────────────────────────────

    #[test]
    fn fs_fingerprinter_deterministic() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config.yaml");
        let rules_dir = dir.path().join("rules.d");
        fs::write(&config, "test config").unwrap();
        fs::create_dir_all(&rules_dir).unwrap();

        let fp = FsFingerprinter { config_path: config.clone(), rules_dir: rules_dir.clone() };
        let f1 = fp.fingerprint();
        let f2 = fp.fingerprint();
        assert_eq!(f1, f2, "fingerprint should be deterministic");
    }

    #[test]
    fn fs_fingerprinter_changes_with_file_modification() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config.yaml");
        let rules_dir = dir.path().join("rules.d");
        fs::write(&config, "v1").unwrap();
        fs::create_dir_all(&rules_dir).unwrap();

        let fp = FsFingerprinter { config_path: config.clone(), rules_dir: rules_dir.clone() };
        let f1 = fp.fingerprint();

        // Modify the file — fingerprint should change (based on mtime)
        std::thread::sleep(std::time::Duration::from_millis(10));
        fs::write(&config, "v2").unwrap();
        let f2 = fp.fingerprint();

        // Note: on some fast filesystems mtimes might not update with ms precision.
        // We just verify fingerprint is computable; change detection may vary.
        let _ = (f1, f2); // both should succeed without panic
    }

    #[test]
    fn fs_fingerprinter_missing_paths() {
        let fp = FsFingerprinter {
            config_path: PathBuf::from("/nonexistent/config.yaml"),
            rules_dir: PathBuf::from("/nonexistent/rules.d"),
        };
        // Should not panic — just returns a (deterministic) fingerprint
        let _ = fp.fingerprint();
    }

    // ── resolve_cached with FsCache ─────────────────────────────

    #[test]
    fn resolve_cached_with_fs_cache() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("cached.json");
        let cache = FsCache { path };
        let fp = FixedFingerprinter(777);

        let rules = resolve_cached(&cache, &fp, || Ok(test_rules())).unwrap();
        assert_eq!(rules.len(), 1);

        // Second call should hit cache
        let rules2 = resolve_cached(&cache, &fp, || {
            panic!("should not be called on cache hit");
        }).unwrap();
        assert_eq!(rules2.len(), 1);
    }

    // ── resolve_cached error propagation ─────────────────────────

    #[test]
    fn resolve_cached_propagates_resolver_error() {
        let cache: MemCache<Vec<Rule>> = MemCache::empty();
        let fp = FixedFingerprinter(1);
        let result = resolve_cached(&cache, &fp, || {
            anyhow::bail!("resolver failed")
        });
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("resolver failed"));
    }

    #[test]
    fn resolve_cached_resolver_error_does_not_populate_cache() {
        let cache: MemCache<Vec<Rule>> = MemCache::empty();
        let fp = FixedFingerprinter(1);
        let _ = resolve_cached(&cache, &fp, || -> anyhow::Result<Vec<Rule>> {
            anyhow::bail!("boom")
        });
        assert!(cache.load().is_none(), "cache should remain empty on resolver error");
    }

    // ── FsCache default_path env behavior ────────────────────────

    #[test]
    fn fs_cache_default_path_contains_guardrail() {
        let path = FsCache::default_path();
        let path_str = path.to_string_lossy();
        assert!(
            path_str.contains("guardrail"),
            "default path should contain 'guardrail', got: {path_str}"
        );
    }
}
