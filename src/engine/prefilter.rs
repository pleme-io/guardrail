use std::collections::HashSet;

use hayai::engine::{Prefilter, contains_ascii_ci};

use crate::model::{PrefilterOverrides, PrefilterSpec};

const DEFAULT_SPEC_YAML: &str = include_str!("../../rules/prefilter.yaml");

#[derive(Debug, Clone)]
pub struct PrefixPrefilter {
    commands: HashSet<String>,
    keywords: Vec<Vec<u8>>,
    markers: Vec<Vec<u8>>,
    start_markers: Vec<String>,
}

impl PrefixPrefilter {
    #[must_use]
    pub fn from_spec(spec: &PrefilterSpec) -> Self {
        Self {
            commands: spec.commands.iter().cloned().collect(),
            keywords: spec
                .keywords
                .iter()
                .map(|k| k.as_bytes().to_vec())
                .collect(),
            markers: spec.markers.iter().map(|m| m.as_bytes().to_vec()).collect(),
            start_markers: spec.start_markers.clone(),
        }
    }

    #[must_use]
    pub fn default_spec() -> PrefilterSpec {
        serde_yaml::from_str(DEFAULT_SPEC_YAML).expect("rules/prefilter.yaml is valid")
    }

    #[must_use]
    pub fn configured(overrides: &PrefilterOverrides) -> Self {
        let mut spec = Self::default_spec();
        spec.commands
            .retain(|c| !overrides.removed_commands.contains(c));
        spec.commands
            .extend(overrides.extra_commands.iter().cloned());
        spec.keywords
            .extend(overrides.extra_keywords.iter().cloned());
        spec.markers.extend(overrides.extra_markers.iter().cloned());
        Self::from_spec(&spec)
    }
}

impl PrefixPrefilter {
    #[must_use]
    pub fn from_user_config() -> Self {
        let overrides = crate::config::load_user_config(&crate::config::config_path())
            .map(|c| c.prefilter)
            .unwrap_or_default();
        Self::configured(&overrides)
    }
}

impl Default for PrefixPrefilter {
    fn default() -> Self {
        Self::from_spec(&Self::default_spec())
    }
}

impl Prefilter for PrefixPrefilter {
    fn is_safe(&self, command: &str) -> bool {
        let trimmed = command.trim_start();
        if self
            .start_markers
            .iter()
            .any(|m| trimmed.starts_with(m.as_str()))
        {
            return false;
        }
        // Scan the first 3 words of EVERY SEGMENT, not the first 3 words of the
        // whole command: `cd /tmp && rm -rf /` puts `rm` at word 4, and a scan
        // over the whole command let it skip the engine (confirmed live,
        // 2026-07-27).
        let has_command = command
            .split(|c| c == ';' || c == '&' || c == '|' || c == '\n')
            .any(|segment| {
                segment.split_whitespace().take(3).any(|word| {
                    self.commands.contains(word)
                        || self.commands.iter().any(|p| word.starts_with(p.as_str()))
                })
            });
        if has_command {
            return false;
        }
        let bytes = command.as_bytes();
        if self.keywords.iter().any(|kw| contains_ascii_ci(bytes, kw)) {
            return false;
        }
        if self
            .markers
            .iter()
            .any(|m| !m.is_empty() && bytes.windows(m.len()).any(|w| w == m.as_slice()))
        {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod chained_bypass_tests {
    use super::*;

    /// A dangerous verb after a safe first command must still reach the DFA.
    ///
    /// Before 2026-07-27 the prefilter took the first 3 words of the WHOLE
    /// command, so a destructive verb chained after `cd` was fast-rejected — it
    /// sat at word 4 and the DFA never ran, which made every rule in every
    /// suite unreachable for that shape. Verified live at the time: the bare
    /// form exited 1, the `cd`-prefixed form exited 0.
    #[test]
    fn a_dangerous_verb_after_a_safe_prefix_is_not_fast_rejected() {
        let p = PrefixPrefilter::default();
        for cmd in [
            "cd /tmp && rm -rf /",
            "cd a && cd b && rm -rf /",
            "git status && kubectl delete namespace prod",
            "cd repo && sed -i.bak 's/a/b/' Cargo.toml",
            "mkdir -p x; cd x; helm uninstall app -n production",
        ] {
            assert!(!p.is_safe(cmd), "must reach the DFA: {cmd}");
        }
    }

    /// The fix must not turn every chained command into a DFA call — the
    /// prefilter exists so the ~99% safe majority costs ~50ns.
    #[test]
    fn genuinely_safe_chains_are_still_fast_rejected() {
        let p = PrefixPrefilter::default();
        // NOTE: `cargo` and `echo` are themselves in DANGEROUS_PREFIXES (the
        // supply-chain and secrets categories), so neither is a valid "safe"
        // fixture — a first draft used both and failed, which was the fixture
        // being wrong rather than the prefilter.
        for cmd in [
            "cd /tmp && ls",
            "cd src && cat main.rs",
            "mkdir build && cd build",
            "ls -la && pwd",
        ] {
            assert!(p.is_safe(cmd), "should stay on the fast path: {cmd}");
        }
    }

    /// The scan stays bounded per segment; it did not silently become an
    /// unbounded whole-command scan.
    #[test]
    fn the_defaults_come_from_the_data_file_and_config_extends_and_trims_them() {
        let d = PrefixPrefilter::default();
        assert!(!d.is_safe("kubectl get pods"));
        assert!(d.is_safe("frobnicate --all"));
        let o = PrefilterOverrides {
            extra_commands: vec!["frobnicate".into()],
            removed_commands: vec!["kubectl".into()],
            extra_keywords: vec!["WIPE ALL".into()],
            extra_markers: vec!["%%".into()],
        };
        let c = PrefixPrefilter::configured(&o);
        assert!(!c.is_safe("frobnicate --all"));
        assert!(c.is_safe("kubectl get pods"));
        assert!(!c.is_safe("tool wipe all now"));
        assert!(!c.is_safe("tool %% now"));
    }

    #[test]
    fn the_scan_is_still_bounded_within_a_segment() {
        let p = PrefixPrefilter::default();
        // `rmdir` prefix-matches `rm`, but sits at word 6 of its segment — past
        // the 3-word window. (`echo` cannot lead this fixture: it is itself a
        // dangerous prefix.)
        assert!(p.is_safe("ls one two three four rmdir"));
    }
}
