use std::collections::HashSet;
use std::sync::LazyLock;

use hayai::engine::{Prefilter, contains_ascii_ci};

/// First-word prefixes that COULD trigger a rule.
const DANGEROUS_PREFIXES: &[&str] = &[
    // filesystem
    "rm", "dd", "mkfs", "chmod", "chown", "mv", "truncate", "shred",
    // git
    "git",
    // database / SQL
    "psql", "mysql", "sqlite3", "sqlcmd", "sqlx", "diesel", "prisma",
    "liquibase", "flyway", "knex", "rails", "rake", "python", "django-admin",
    "mongosh", "mongo",
    // kubernetes
    "kubectl", "helm", "flux",
    // cloud
    "aws", "gcloud", "gsutil", "az", "bq",
    // nix
    "nix", "nix-collect-garbage",
    // docker
    "docker",
    // secrets
    "sops", "echo",
    // terraform / iac
    //
    // `tofu` is the OpenTofu binary — a drop-in successor to `terraform` and
    // what this fleet actually invokes. Its absence here was a silent hole: the
    // prefilter fast-rejects before the DFA runs, so ANY `tofu` rule — existing
    // or future — never reached the engine at all. A rule that cannot be
    // reached is a guard over zero subjects.
    "terraform", "tofu", "pulumi", "ansible-playbook",
    // stream editors
    //
    // In-place edits (`sed -i`, `perl -i`) of structured files are the class
    // this covers: the editor cannot see the file's grammar, so it can leave
    // something that still parses but means something else.
    "sed", "perl", "awk",
    // akeyless
    "akeyless", "aky",
    // process
    "kill", "killall", "pkill", "shutdown", "poweroff", "halt", "reboot",
    "systemctl", "launchctl",
    // network
    "iptables", "ufw", "ip", "nft",
    // nosql
    "redis-cli",
    // curl/wget (pipe install, elasticsearch)
    "curl", "wget",
    // mysql admin
    "mysqladmin",
    // shell wrappers -- commands that execute other commands
    "sh", "bash", "zsh", "fish", "dash",
    "env", "sudo", "doas", "nohup", "nice", "timeout",
    // eval / indirect execution
    "eval", "xargs", "find",
    // scheduling
    "crontab", "at",
    // disk partitioning
    "fdisk", "parted", "wipefs",
    // sync/publish (supply chain)
    "npm", "cargo", "gem", "pip", "twine",
    // remote sync
    "rsync", "rclone",
    // log wiping
    "journalctl",
    // ssh (remote command execution)
    "ssh",
];

static PREFIX_SET: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| DANGEROUS_PREFIXES.iter().copied().collect());

/// SQL keywords checked in a zero-alloc byte-level scan.
const SQL_KEYWORDS: &[&[u8]] = &[
    b"DROP ", b"TRUNCATE ", b"DELETE FROM", b"REVOKE ",
    b"FLUSHALL", b"FLUSHDB", b"VACUUM FULL",
    b"BASE64", b"| BASH", b"| SH",
];

/// Production prefilter: skips DFA for commands whose first 3 words
/// don't match a known dangerous prefix AND don't contain SQL keywords.
///
/// Safe commands (~99%): ~50ns. Dangerous commands: forwarded to DFA.
#[derive(Debug, Clone, Copy, Default)]
pub struct PrefixPrefilter;

impl PrefixPrefilter {
    /// Access the static set of dangerous prefixes (for test utilities).
    #[must_use]
    pub fn prefix_set() -> &'static HashSet<&'static str> {
        &PREFIX_SET
    }
}

impl Prefilter for PrefixPrefilter {
    fn is_safe(&self, command: &str) -> bool {
        let trimmed = command.trim_start();
        if trimmed.starts_with('$') || trimmed.contains('`') {
            return false;
        }
        // Scan the first 3 words of EVERY SEGMENT, not the first 3 words of the
        // whole command.
        //
        // A dangerous verb sits near the start of *its own* segment, but a
        // chained command pushes it arbitrarily far from the start of the
        // string. A bare `.take(3)` over the whole command therefore had a
        // trivial bypass, confirmed live before this fix:
        //
        //     rm -rf /                 -> `rm` at word 1  -> blocked
        //     true && rm -rf /         -> `rm` at word 3  -> blocked
        //     cd /tmp && rm -rf /      -> `rm` at word 4  -> ALLOWED
        //
        // The last one never reached the DFA at all, so every rule in every
        // suite was unreachable for it. Splitting on separators first keeps the
        // cheap bounded-scan property (still at most 3 words per segment) while
        // making position-in-the-string irrelevant.
        let has_dangerous_prefix = command
            .split(|c| c == ';' || c == '&' || c == '|' || c == '\n')
            .any(|segment| {
                segment.split_whitespace().take(3).any(|word| {
                    PREFIX_SET.contains(word) || PREFIX_SET.iter().any(|p| word.starts_with(p))
                })
            });
        if has_dangerous_prefix {
            return false;
        }
        let bytes = command.as_bytes();
        if SQL_KEYWORDS.iter().any(|kw| contains_ascii_ci(bytes, kw)) {
            return false;
        }
        if bytes.windows(2).any(|w| w == b"/*")
            || bytes.windows(3).any(|w| w == b"-- " || w == b"--\t")
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
        let p = PrefixPrefilter;
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
        let p = PrefixPrefilter;
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
    fn the_scan_is_still_bounded_within_a_segment() {
        let p = PrefixPrefilter;
        // `rmdir` prefix-matches `rm`, but sits at word 6 of its segment — past
        // the 3-word window. (`echo` cannot lead this fixture: it is itself a
        // dangerous prefix.)
        assert!(p.is_safe("ls one two three four rmdir"));
    }
}
