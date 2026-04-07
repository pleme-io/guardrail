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
    "terraform", "pulumi", "ansible-playbook",
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
        let has_dangerous_prefix = command
            .split_whitespace()
            .take(3)
            .any(|word| PREFIX_SET.contains(word) || PREFIX_SET.iter().any(|p| word.starts_with(p)));
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
