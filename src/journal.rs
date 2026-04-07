//! Write journal — tracks recently written files for chaining detection.
//!
//! When a Write/Edit tool writes a file with dangerous content, we record
//! it. When Bash subsequently executes that file, we can detect the chain.
//!
//! Journal location: `$XDG_RUNTIME_DIR/guardrail/write-journal.json`
//! (falls back to `$TMPDIR/guardrail-journal.json`).
//!
//! Entries expire after 5 minutes to avoid stale state.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, fs};

use serde::{Deserialize, Serialize};

/// TTL for journal entries (5 minutes).
const ENTRY_TTL_SECS: u64 = 300;

/// Script extensions recognized by `extract_executed_paths`.
const SCRIPT_EXTENSIONS: &[&str] = &[".sh", ".bash", ".py", ".rb", ".pl", ".zsh"];

/// Shell command prefixes that take a script path as the next non-flag argument.
const SHELL_INTERPRETERS: &[&str] = &["bash", "sh", "zsh", "python", "python3", "ruby", "perl"];

/// A journal entry recording a written file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    /// Whether the content was flagged as dangerous.
    pub dangerous: bool,
    /// Unix timestamp when the entry was recorded.
    pub timestamp: u64,
}

/// The on-disk journal structure. Keys are file paths.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WriteJournal {
    pub entries: HashMap<String, JournalEntry>,
}

impl WriteJournal {
    /// Load the journal from the default path.
    /// Returns empty journal if file missing or corrupt.
    #[must_use]
    pub fn load() -> Self {
        Self::load_from(&default_journal_path())
    }

    /// Load the journal from a specific path (for testing).
    #[must_use]
    pub fn load_from(path: &Path) -> Self {
        let Ok(content) = fs::read_to_string(path) else {
            return Self::default();
        };
        serde_json::from_str(&content).unwrap_or_default()
    }

    /// Save the journal to the default path.
    ///
    /// # Errors
    ///
    /// Returns an error if parent directories can't be created or the
    /// journal file can't be written.
    pub fn save(&self) -> anyhow::Result<()> {
        self.save_to(&default_journal_path())
    }

    /// Save the journal to a specific path (for testing).
    ///
    /// # Errors
    ///
    /// Returns an error if parent directories can't be created or the
    /// file can't be written.
    pub fn save_to(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string(self)?;
        fs::write(path, content)?;
        Ok(())
    }

    /// Record a file write. Prunes expired entries first.
    pub fn record(&mut self, file_path: &str, dangerous: bool) {
        self.prune();
        self.entries.insert(
            file_path.to_owned(),
            JournalEntry {
                dangerous,
                timestamp: now_secs(),
            },
        );
    }

    /// Check if a file path was recently written with dangerous content.
    #[must_use]
    pub fn is_dangerous(&self, file_path: &str) -> bool {
        let now = now_secs();
        self.entries.get(file_path).is_some_and(|e| {
            e.dangerous && now.saturating_sub(e.timestamp) < ENTRY_TTL_SECS
        })
    }

    /// Remove expired entries.
    pub fn prune(&mut self) {
        let now = now_secs();
        self.entries
            .retain(|_, e| now.saturating_sub(e.timestamp) < ENTRY_TTL_SECS);
    }
}

/// Extract file paths that a Bash command might execute.
///
/// Heuristic (single pass): for each word, check if it's a direct script path
/// or if it follows a shell interpreter prefix.
#[must_use]
pub fn extract_executed_paths(command: &str) -> Vec<String> {
    let mut paths = Vec::new();
    let words: Vec<&str> = command.split_whitespace().collect();

    let mut i = 0;
    while i < words.len() {
        let word = words[i];
        let basename = Path::new(word)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(word);

        // Check if this word is a shell interpreter
        if SHELL_INTERPRETERS.contains(&basename) {
            // Next non-flag argument is the script path
            for next in &words[i + 1..] {
                if !next.starts_with('-') {
                    paths.push((*next).to_owned());
                    break;
                }
            }
        }

        // Check if this word is a direct script path
        if is_path_like(word) && has_script_extension(word) {
            paths.push(word.to_owned());
        }

        i += 1;
    }

    paths.sort();
    paths.dedup();
    paths
}

/// Whether a word looks like a file path.
fn is_path_like(word: &str) -> bool {
    word.starts_with('/')
        || word.starts_with("./")
        || word.starts_with("~/")
}

/// Whether a word ends with a known script extension.
fn has_script_extension(word: &str) -> bool {
    SCRIPT_EXTENSIONS.iter().any(|ext| word.ends_with(ext))
}

/// Default journal file path.
fn default_journal_path() -> PathBuf {
    if let Ok(runtime) = env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(runtime)
            .join("guardrail")
            .join("write-journal.json")
    } else if let Ok(tmpdir) = env::var("TMPDIR") {
        // macOS sets $TMPDIR to a per-user temp directory
        PathBuf::from(tmpdir).join("guardrail-journal.json")
    } else {
        // Last resort: use user name for isolation
        let user = env::var("USER").unwrap_or_else(|_| "unknown".into());
        PathBuf::from(format!("/tmp/guardrail-journal-{user}.json"))
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ── In-memory journal ───────────────────────────────────────

    #[test]
    fn journal_record_and_check() {
        let mut journal = WriteJournal::default();
        journal.record("/tmp/evil.sh", true);
        assert!(journal.is_dangerous("/tmp/evil.sh"));
        assert!(!journal.is_dangerous("/tmp/safe.sh"));
    }

    #[test]
    fn journal_safe_write_not_dangerous() {
        let mut journal = WriteJournal::default();
        journal.record("/tmp/safe.sh", false);
        assert!(!journal.is_dangerous("/tmp/safe.sh"));
    }

    #[test]
    fn journal_empty_not_dangerous() {
        let journal = WriteJournal::default();
        assert!(!journal.is_dangerous("/tmp/anything.sh"));
    }

    #[test]
    fn journal_overwrite_replaces_entry() {
        let mut journal = WriteJournal::default();
        journal.record("/tmp/file.sh", true);
        assert!(journal.is_dangerous("/tmp/file.sh"));
        journal.record("/tmp/file.sh", false);
        assert!(!journal.is_dangerous("/tmp/file.sh"));
    }

    #[test]
    fn journal_prune_removes_expired() {
        let mut journal = WriteJournal::default();
        // Insert an entry with a timestamp far in the past
        journal.entries.insert(
            "/tmp/old.sh".to_owned(),
            JournalEntry {
                dangerous: true,
                timestamp: 1000, // way in the past
            },
        );
        journal.entries.insert(
            "/tmp/new.sh".to_owned(),
            JournalEntry {
                dangerous: true,
                timestamp: now_secs(),
            },
        );
        journal.prune();
        assert!(!journal.entries.contains_key("/tmp/old.sh"));
        assert!(journal.entries.contains_key("/tmp/new.sh"));
    }

    #[test]
    fn journal_expired_entry_not_dangerous() {
        let mut journal = WriteJournal::default();
        journal.entries.insert(
            "/tmp/expired.sh".to_owned(),
            JournalEntry {
                dangerous: true,
                timestamp: 1000,
            },
        );
        assert!(!journal.is_dangerous("/tmp/expired.sh"));
    }

    // ── Disk round-trip ─────────────────────────────────────────

    #[test]
    fn journal_disk_round_trip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test-journal.json");

        let mut journal = WriteJournal::default();
        journal.record("/tmp/evil.sh", true);
        journal.record("/tmp/safe.sh", false);
        journal.save_to(&path).unwrap();

        let loaded = WriteJournal::load_from(&path);
        assert!(loaded.is_dangerous("/tmp/evil.sh"));
        assert!(!loaded.is_dangerous("/tmp/safe.sh"));
        assert_eq!(loaded.entries.len(), 2);
    }

    #[test]
    fn journal_load_missing_file_returns_empty() {
        let journal = WriteJournal::load_from(Path::new("/nonexistent/journal.json"));
        assert!(journal.entries.is_empty());
    }

    #[test]
    fn journal_load_corrupt_file_returns_empty() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("corrupt.json");
        fs::write(&path, "not valid json {{{").unwrap();
        let journal = WriteJournal::load_from(&path);
        assert!(journal.entries.is_empty());
    }

    // ── extract_executed_paths ───────────────────────────────────

    #[test]
    fn extract_paths_bash_script() {
        let paths = extract_executed_paths("bash /tmp/evil.sh");
        assert!(paths.contains(&"/tmp/evil.sh".to_owned()));
    }

    #[test]
    fn extract_paths_direct_script() {
        let paths = extract_executed_paths("/tmp/deploy.sh --prod");
        assert!(paths.contains(&"/tmp/deploy.sh".to_owned()));
    }

    #[test]
    fn extract_paths_python() {
        let paths = extract_executed_paths("python3 /tmp/script.py");
        assert!(paths.contains(&"/tmp/script.py".to_owned()));
    }

    #[test]
    fn extract_paths_no_scripts() {
        let paths = extract_executed_paths("ls -la /tmp");
        assert!(paths.is_empty());
    }

    #[test]
    fn extract_paths_relative() {
        let paths = extract_executed_paths("./deploy.sh");
        assert!(paths.contains(&"./deploy.sh".to_owned()));
    }

    #[test]
    fn extract_paths_shell_with_flags() {
        let paths = extract_executed_paths("bash -x -e /tmp/test.sh");
        assert!(paths.contains(&"/tmp/test.sh".to_owned()));
    }

    #[test]
    fn extract_paths_tilde() {
        let paths = extract_executed_paths("~/scripts/deploy.sh --env prod");
        assert!(paths.contains(&"~/scripts/deploy.sh".to_owned()));
    }

    #[test]
    fn extract_paths_no_extension() {
        // Files without script extensions are not detected (by design)
        let paths = extract_executed_paths("bash /tmp/binary");
        // Still detected because bash is an interpreter prefix
        assert!(paths.contains(&"/tmp/binary".to_owned()));
    }

    #[test]
    fn extract_paths_deduplicates() {
        // `bash /tmp/evil.sh` gives both interpreter match AND direct path match
        let paths = extract_executed_paths("bash /tmp/evil.sh");
        assert_eq!(
            paths.iter().filter(|p| *p == "/tmp/evil.sh").count(),
            1,
            "expected exactly one /tmp/evil.sh, got: {paths:?}"
        );
    }

    // ── Helpers ─────────────────────────────────────────────────

    #[test]
    fn is_path_like_checks() {
        assert!(is_path_like("/usr/bin/foo"));
        assert!(is_path_like("./script.sh"));
        assert!(is_path_like("~/bin/bar.sh"));
        assert!(!is_path_like("plain"));
        assert!(!is_path_like("--flag"));
    }

    #[test]
    fn has_script_extension_checks() {
        assert!(has_script_extension("foo.sh"));
        assert!(has_script_extension("bar.py"));
        assert!(has_script_extension("baz.rb"));
        assert!(!has_script_extension("binary"));
        assert!(!has_script_extension("file.txt"));
    }

    // ── extract_executed_paths edge cases ────────────────────────

    #[test]
    fn extract_paths_empty_command() {
        let paths = extract_executed_paths("");
        assert!(paths.is_empty());
    }

    #[test]
    fn extract_paths_whitespace_only() {
        let paths = extract_executed_paths("   ");
        assert!(paths.is_empty());
    }

    #[test]
    fn extract_paths_multiple_interpreters() {
        let paths = extract_executed_paths("bash /tmp/a.sh && python3 /tmp/b.py");
        assert!(paths.contains(&"/tmp/a.sh".to_owned()));
        assert!(paths.contains(&"/tmp/b.py".to_owned()));
    }

    #[test]
    fn extract_paths_ruby_interpreter() {
        let paths = extract_executed_paths("ruby /opt/script.rb");
        assert!(paths.contains(&"/opt/script.rb".to_owned()));
    }

    #[test]
    fn extract_paths_perl_interpreter() {
        let paths = extract_executed_paths("perl /opt/script.pl");
        assert!(paths.contains(&"/opt/script.pl".to_owned()));
    }

    #[test]
    fn extract_paths_zsh_interpreter() {
        let paths = extract_executed_paths("zsh ./setup.zsh");
        assert!(paths.contains(&"./setup.zsh".to_owned()));
    }

    #[test]
    fn extract_paths_sh_interpreter() {
        let paths = extract_executed_paths("sh /tmp/run.sh");
        assert!(paths.contains(&"/tmp/run.sh".to_owned()));
    }

    #[test]
    fn extract_paths_no_flag_args() {
        let paths = extract_executed_paths("python3 -u -B script.py");
        // "script.py" is not path-like (no leading / ./ ~/) so only interpreter match
        assert!(paths.contains(&"script.py".to_owned()));
    }

    #[test]
    fn extract_paths_bare_word_not_path() {
        let paths = extract_executed_paths("echo hello world");
        assert!(paths.is_empty());
    }

    #[test]
    fn extract_paths_direct_bash_extension() {
        let paths = extract_executed_paths("/usr/local/bin/setup.bash");
        assert!(paths.contains(&"/usr/local/bin/setup.bash".to_owned()));
    }

    #[test]
    fn extract_paths_multiple_direct_scripts() {
        let paths = extract_executed_paths("./a.sh && ./b.py && ./c.rb");
        assert!(paths.contains(&"./a.sh".to_owned()));
        assert!(paths.contains(&"./b.py".to_owned()));
        assert!(paths.contains(&"./c.rb".to_owned()));
    }

    // ── Journal record + prune interaction ──────────────────────

    #[test]
    fn record_auto_prunes() {
        let mut journal = WriteJournal::default();
        journal.entries.insert(
            "/tmp/old.sh".to_owned(),
            JournalEntry { dangerous: true, timestamp: 1000 },
        );
        // record should prune the stale entry
        journal.record("/tmp/new.sh", true);
        assert!(!journal.entries.contains_key("/tmp/old.sh"));
        assert!(journal.entries.contains_key("/tmp/new.sh"));
    }

    #[test]
    fn record_multiple_files() {
        let mut journal = WriteJournal::default();
        journal.record("/tmp/a.sh", true);
        journal.record("/tmp/b.sh", false);
        journal.record("/tmp/c.sh", true);
        assert_eq!(journal.entries.len(), 3);
        assert!(journal.is_dangerous("/tmp/a.sh"));
        assert!(!journal.is_dangerous("/tmp/b.sh"));
        assert!(journal.is_dangerous("/tmp/c.sh"));
    }

    #[test]
    fn prune_all_expired() {
        let mut journal = WriteJournal::default();
        journal.entries.insert(
            "/tmp/a.sh".to_owned(),
            JournalEntry { dangerous: true, timestamp: 100 },
        );
        journal.entries.insert(
            "/tmp/b.sh".to_owned(),
            JournalEntry { dangerous: true, timestamp: 200 },
        );
        journal.prune();
        assert!(journal.entries.is_empty());
    }

    #[test]
    fn prune_keeps_fresh() {
        let mut journal = WriteJournal::default();
        let now = now_secs();
        journal.entries.insert(
            "/tmp/fresh.sh".to_owned(),
            JournalEntry { dangerous: true, timestamp: now },
        );
        journal.prune();
        assert_eq!(journal.entries.len(), 1);
    }

    // ── Journal disk operations ─────────────────────────────────

    #[test]
    fn journal_save_creates_parent_dirs() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("deep/nested/journal.json");
        let journal = WriteJournal::default();
        journal.save_to(&path).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn journal_round_trip_preserves_timestamps() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("ts-test.json");
        let now = now_secs();

        let mut journal = WriteJournal::default();
        journal.entries.insert(
            "/tmp/ts.sh".to_owned(),
            JournalEntry { dangerous: true, timestamp: now },
        );
        journal.save_to(&path).unwrap();

        let loaded = WriteJournal::load_from(&path);
        let entry = loaded.entries.get("/tmp/ts.sh").unwrap();
        assert_eq!(entry.timestamp, now);
        assert!(entry.dangerous);
    }

    // ── is_path_like edge cases ─────────────────────────────────

    #[test]
    fn is_path_like_edge_cases() {
        assert!(!is_path_like(""));
        assert!(!is_path_like("-"));
        assert!(!is_path_like("~notapath"));
        assert!(is_path_like("~/"));
        assert!(!is_path_like("relative/path"));
    }

    // ── has_script_extension edge cases ──────────────────────────

    #[test]
    fn has_script_extension_all_types() {
        for ext in SCRIPT_EXTENSIONS {
            let filename = format!("test{ext}");
            assert!(has_script_extension(&filename), "expected {filename} to have script extension");
        }
    }

    #[test]
    fn has_script_extension_false_positives() {
        assert!(!has_script_extension("file.pyc"));
        assert!(!has_script_extension("file.shell"));
        assert!(!has_script_extension("file.rs"));
    }

    // ── extract_executed_paths: interpreter at end of command ────

    #[test]
    fn extract_paths_interpreter_at_end_no_script() {
        let paths = extract_executed_paths("echo hello && bash");
        assert!(paths.is_empty(), "bare interpreter with no script should yield nothing");
    }

    #[test]
    fn extract_paths_full_path_interpreter() {
        let paths = extract_executed_paths("/usr/bin/bash /tmp/script.sh");
        assert!(paths.contains(&"/tmp/script.sh".to_owned()));
    }

    #[test]
    fn extract_paths_python3_full_path() {
        let paths = extract_executed_paths("/usr/local/bin/python3 /opt/app.py");
        assert!(paths.contains(&"/opt/app.py".to_owned()));
    }

    // ── default_journal_path smoke test ──────────────────────────

    #[test]
    fn default_journal_path_is_absolute() {
        let path = default_journal_path();
        assert!(
            path.is_absolute(),
            "journal path should be absolute, got: {}",
            path.display()
        );
    }

    #[test]
    fn default_journal_path_contains_guardrail() {
        let path = default_journal_path();
        let path_str = path.to_string_lossy();
        assert!(
            path_str.contains("guardrail"),
            "journal path should contain 'guardrail', got: {path_str}"
        );
    }

    // ── journal serde ────────────────────────────────────────────

    #[test]
    fn journal_serde_round_trip() {
        let mut journal = WriteJournal::default();
        journal.record("/tmp/test.sh", true);
        let json = serde_json::to_string(&journal).unwrap();
        let loaded: WriteJournal = serde_json::from_str(&json).unwrap();
        assert!(loaded.is_dangerous("/tmp/test.sh"));
    }

    #[test]
    fn journal_entry_serde() {
        let entry = JournalEntry {
            dangerous: true,
            timestamp: 12345,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: JournalEntry = serde_json::from_str(&json).unwrap();
        assert!(back.dangerous);
        assert_eq!(back.timestamp, 12345);
    }

    // ── now_secs sanity ──────────────────────────────────────────

    #[test]
    fn now_secs_returns_reasonable_value() {
        let ts = now_secs();
        assert!(ts > 1_700_000_000, "timestamp should be recent, got: {ts}");
    }
}
