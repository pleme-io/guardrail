# guardrail

**Defensive guardrails for AI coding agents.** AI agents execute shell commands.
Some are catastrophic and irreversible — `rm -rf /`, `DROP TABLE`,
`terraform destroy`, `kubectl delete namespace`. Telling an agent to "be careful"
is the honor system. **guardrail replaces the honor system with code.**

`guardrail` is a Rust binary that intercepts every shell command *before*
execution, pattern-matches it against destructive operations, and blocks the
dangerous ones — not with a prompt or a warning, but with a hard rejection the
agent harness honors. A safe command is waved through in ~50 ns without a heap
allocation; a dangerous one is matched against ~2,500 rules in single-digit
microseconds.

> Part of the [pleme-io](https://github.com/pleme-io) substrate. Operates under
> Constructive Substrate Engineering — see `CLAUDE.md`.

---

## Why

Context tells an agent what it knows. Skills tell it what it can do. guardrail is
the other axis: **what the agent must not do** — a defensive boundary enforced in
code rather than prose. Even with zero configuration, the compiled-in defaults
catch the most dangerous operations. Wire the hook once and every command an
agent tries to run is checked.

guardrail is **defensive only**: it blocks dangerous operations, it never
performs them.

---

## How a command gets checked

Every command flows through a three-stage pipeline, fastest first. The engine is
generic over its preprocessing — `RegexEngine<N: Normalizer, P: Prefilter>` —
so production uses zero-cost defaults and tests substitute isolating
implementations through the same type.

```
Agent says: "run this command"
    │
    ▼
┌─────────────────────────────┐
│ 1. NORMALIZE                │  trait Normalizer → Cow<str>
│    Strip /nix/store/ paths  │  NixStoreNormalizer (prod) / IdentityNormalizer (test)
│    Cow::Borrowed when clean │  ZERO ALLOCATION on the 99%+ of commands with no path
└─────────────┬───────────────┘
              ▼
┌─────────────────────────────┐
│ 2. PREFILTER                │  trait Prefilter → bool
│    Scan leading words vs a  │  PrefixPrefilter (prod) / NullPrefilter (test)
│    known-dangerous prefix   │  + byte-level case-insensitive SQL keyword scan
│    set; no Vec, no upper()  │  ZERO ALLOCATION — ~99% of commands exit here in ~50 ns
└─────────────┬───────────────┘
              │ (only dangerous prefixes continue)
              ▼
┌─────────────────────────────┐
│ 3. REGEXSET DFA             │  all rules compiled into ONE DFA
│    Single-pass match across │  O(input_length), not O(pattern_count)
│    every pattern at once    │  early-exit on first Block
│    Block → JSON reject      │
│    Warn  → stderr only      │
│    Allow → silent pass      │
└─────────────────────────────┘
```

Safe commands like `ls`, `cargo test`, `git status` exit at stage 2 — they never
touch the regex engine. Only commands beginning with a known-dangerous prefix
(`rm`, `git`, `kubectl`, `aws`, `psql`, `terraform`, …) reach the full DFA match.

### Beyond single-command matching

- **Write-journal chaining detection** — when a `Write`/`Edit` lands dangerous
  content on disk, it is journaled (`$XDG_RUNTIME_DIR/guardrail/write-journal.json`,
  entries expire after 5 minutes). A later `Bash` call that executes that file is
  caught as a chain, not just per command.
- **Touch ID bypass** (macOS) — when a rule blocks, an interactive user can
  authenticate via Touch ID to override that single block: a hardware-backed
  "are you sure?" that never requires disabling the rule. A no-op on non-macOS
  platforms or in non-TTY contexts.

---

## Install / build

Nix flake (preferred):

```bash
nix build              # build the binary
nix run . -- list      # run a subcommand
```

Cargo:

```bash
cargo build --release
cargo test             # 171 tests, including auto-derived per-rule validation
```

Edition 2024, Rust 1.89.0+, MIT.

---

## CLI

```bash
guardrail check      # read hook JSON from stdin, emit a decision (the hook entrypoint)
guardrail compile    # pre-compile rules to ~/.cache/guardrail/compiled.json
guardrail validate   # validate the config file + all rules
guardrail list       # show every active rule
```

`check` is what an agent's pre-tool hook invokes; the others are operator tools.

---

## What gets blocked

**~2,500 rules across 14 categories**: `filesystem`, `git`, `database`,
`kubernetes`, `nix`, `docker`, `secrets`, `terraform`, `cloud`, `flux`,
`process`, `network`, `nosql`, and more.

### Compiled-in defaults (always active, zero config)

| Category | Examples | Severity |
|----------|----------|----------|
| Filesystem | `rm -rf /`, `dd of=/dev/sda`, `mkfs` | Block |
| Git | force-push to main, `reset --hard`, `clean -f` | Block / Warn |
| Database | `DROP TABLE`, `TRUNCATE`, `DELETE` without `WHERE` | Block |
| Kubernetes | delete namespace, `delete --all`, helm uninstall prod | Block |
| Nix | `collect-garbage -d`, `store gc` | Warn |
| Docker | `system prune`, `volume prune` | Warn |
| Secrets | decrypt-and-pipe, echo of secret vars | Warn |
| Terraform | `destroy`, `force-unlock`, `state rm`, `pulumi destroy` | Block |
| Flux | uninstall, delete source / kustomization | Block / Warn |

### Plugin suites (deployed to `~/.config/guardrail/rules.d/`)

| Suite | Rules | Coverage |
|-------|------:|----------|
| `sql.yaml` | 45 | `DROP` across object types, `ALTER … DROP COLUMN`, `REVOKE`, migration tools (sqlx, diesel, prisma, liquibase, flyway, rails, django) |
| `aws.yaml` | 26 | EC2, S3, RDS, EKS, IAM, Lambda, CloudFormation, Route53, KMS |
| `aws-generated.yaml` | ~2,250 | **every AWS service** — auto-generated from the AWS SDK models |
| `azure.yaml` | 18 | VM, AKS, SQL, CosmosDB, Storage, KeyVault, DNS |
| `gcp.yaml` | 14 | Compute, GKE, SQL, Spanner, Storage, Functions, Pub/Sub |
| `nosql.yaml` | 8 | Redis `FLUSHALL`, MongoDB drop, Elasticsearch delete, Cassandra `DROP KEYSPACE` |
| `process.yaml` | 6 | `kill -9`, `shutdown`, `systemctl stop` of critical units |
| `network.yaml` | 6 | `iptables -F`, `ufw disable`, `nft flush` |

Each suite is independently toggleable; each individual rule is disableable by
name.

### Rule format

```yaml
- name: rm-rf-root
  pattern: 'rm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/\s*$'
  severity: block
  message: "Recursive force-delete from root"
  category: filesystem
  test_block: "rm -rf /"        # optional: this command MUST match the pattern
  test_allow: "rm -rf ./target" # optional: this command must NOT match
```

---

## Auto-generation from API specs

Hand-writing rules doesn't scale to cover every cloud API. The sibling tool
[guardrail-gen](https://github.com/pleme-io/guardrail-gen) generates rules — with
their test cases — straight from OpenAPI specs and AWS SDK models:

```
API spec (OpenAPI / AWS SDK)
    │  parse every operation
    ▼  filter: is_destructive()  (DELETE method, or name contains
    │     delete/destroy/terminate/remove/purge/revoke/drop/truncate/…)
    ▼  classify risk tier        (database/key/secret → block; tag/metric → warn)
    ▼  emit CLI regex pattern    (operationId → kebab-case)
    ▼  emit test_block + test_allow  (deterministic — the generator knows the CLI syntax)
    ▼
rules.d/{service}.yaml
```

Because the generator knows the exact CLI syntax at generation time, the test
commands are deterministic — no regex reverse-engineering. New API coverage is
one `guardrail-gen generate` away.

---

## Configuration

`~/.config/guardrail/guardrail.yaml` (shikumi convention):

```yaml
categories:
  cloud: false              # disable an entire category
disabledRules:
  - rm-rf-root              # disable a specific rule by name
extraRules:
  - name: protect-prod-db
    pattern: 'psql.*production'
    severity: block
    message: "Direct production database access"
    category: database
```

Five scope levels, broad to narrow: master toggle → category → suite → individual
rule → custom additions.

---

## Performance

The binary runs on every command, so it must be fast.

| Path | Time | Allocation |
|------|------|-----------|
| Safe command (prefilter rejects at prefix) | ~50 ns | zero |
| Dangerous command, cached rules (DFA) | ~1–13 ms | zero in the matcher (`Cow::Borrowed`) |
| Full compile (~2,500 rules) | ~300 ms | `RegexSet` DFA build + cache write |
| First invocation (cold) | ~320 ms | full compile, then cached |

`RegexSet` compiles every pattern into a single DFA: one pass through the input
regardless of rule count — O(input_length), not O(pattern_count). Compiled rules
are cached at `~/.cache/guardrail/compiled.json` and invalidated by a fingerprint
over the config + rule-directory mtimes, so steady-state startup is a single JSON
deserialize.

---

## Testing

**171 tests** validate every rule at two levels — and the test commands are
**auto-derived from the patterns**, so a new rule is exercised without anyone
writing a test by hand:

| Level | Validates | Coverage |
|-------|-----------|----------|
| Regex | the (derived or declared) test command matches each pattern | every rule |
| Engine | the test command produces the right decision through the full pipeline | every rule |
| Benchmark | compile time + per-rule match time stay within thresholds | every rule |
| Unit | normalizer, prefilter, `Display`, edge cases (empty, unicode, long) | all code paths |
| CLI integration | hook JSON → decision, end-to-end | many scenarios |

Rules with explicit `test_block` / `test_allow` take priority; otherwise a
matching command is synthesized from the regex. `Rule::builder("name", "pattern")
.severity(Warn).build()` keeps test construction terse.

---

## Agent integration

guardrail is agent-agnostic — the same binary, config, suites, and cache protect
any agent with a pre-execution hook:

| Agent | Hook event |
|-------|------------|
| Claude Code | `PreToolUse` (Bash matcher) |
| Cursor | `preToolUse` |

Adding guardrail to a new agent is one line of hook wiring; everything else is
shared.

In the pleme-io fleet the wiring is declarative: a `blackmatter-claude`
home-manager module deploys `guardrail.yaml`, copies the enabled suites into
`rules.d/`, wires the hook into the agent's settings, and runs `guardrail compile`
from a `home.activation` hook — so every workstation gets the same guardrails by
construction.

---

## Architecture

The matching primitives — `Normalizer`, `Prefilter`, `RuleEngine`, `CacheStore`,
`Fingerprinter` — come from the shared [`hayai`](https://crates.io/crates/hayai)
crate and are re-exported from `guardrail`'s root, so production and test wiring
differ only by type parameter:

```rust
RegexEngine::new(rules)                                             // production
RegexEngine::with_plugins(rules, IdentityNormalizer, NullPrefilter) // full-DFA test
```

| Trait | Purpose | Production | Testing |
|-------|---------|-----------|---------|
| `Normalizer` | command preprocessing (`Cow<str>`, zero-alloc) | `NixStoreNormalizer` | `IdentityNormalizer` |
| `Prefilter` | fast-reject safe commands (zero-alloc byte scan) | `PrefixPrefilter` | `NullPrefilter` |
| `RuleEngine` | match commands against rules | `RegexEngine<N, P>` | via `with_plugins` |
| `RuleProvider` | composable rule sources | `DefaultsProvider`, `DirectoryProvider` | `MockProvider` |
| `CacheStore` | persist compiled rules | `FsCache` | `MemCache` |
| `Fingerprinter` | detect config staleness | `FsFingerprinter` | `FixedFingerprinter` |

| Module | Responsibility |
|--------|----------------|
| `model` | data types, builder, `Display` impls (`Rule`, `Decision`, `Severity`, `Category`) |
| `engine` | matching pipeline + traits (`RegexEngine`, `NixStoreNormalizer`, `PrefixPrefilter`) |
| `config` | rule resolution + providers (`DefaultsProvider`, `DirectoryProvider`) |
| `cache` | fingerprint-based caching of compiled rules |
| `hook` | agent hook-JSON parsing (`HookInput`, `parse_reader`, `extract_command`) |
| `journal` | write-journal for chained-execution detection |
| `biometric` | Touch ID bypass on macOS |
| `testing` | auto-derived per-rule validation + benchmarks |

---

## Design principles

- **Defense in depth** — compiled-in defaults (always active) + plugin suites
  (deployed) + custom rules (user-defined). Even with zero config the defaults
  catch the worst operations.
- **Zero-config protection** — the binary ships with working compiled-in rules.
  Install, wire the hook, done.
- **Performance by construction** — one DFA for all patterns; a zero-alloc
  prefilter that skips the DFA for ~99% of commands; a cache that eliminates YAML
  parsing after first run. The ceiling is process startup, not matching.
- **Fully testable** — every external dependency (filesystem, cache, rule source,
  normalizer, prefilter) sits behind a trait with a test implementation; every
  rule is validated at regex + engine level.
- **Auto-generatable** — rules and their test cases are emitted from any OpenAPI
  spec or SDK model by a deterministic filter + risk classifier.

---

## Related

| Repo | Purpose |
|------|---------|
| [guardrail](https://github.com/pleme-io/guardrail) | the binary — `check` / `compile` / `validate` / `list` |
| [guardrail-gen](https://github.com/pleme-io/guardrail-gen) | auto-generate rules + test cases from OpenAPI / SDK specs |

---

## License

MIT.
