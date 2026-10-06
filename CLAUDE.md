# guardrail — Defensive Guardrails for AI Coding Agents

> **★★★ CSE / Knowable Construction.** This repo operates under **Constructive Substrate Engineering** — canonical specification at [`pleme-io/theory/CONSTRUCTIVE-SUBSTRATE-ENGINEERING.md`](https://github.com/pleme-io/theory/blob/main/CONSTRUCTIVE-SUBSTRATE-ENGINEERING.md). The Compounding Directive (operational rules: solve once, load-bearing fixes only, idiom-first, models stay current, direction beats velocity) is in the org-level pleme-io/CLAUDE.md ★★★ section. Read both before non-trivial changes.


Block destructive commands via Claude Code PreToolUse hooks. 2,468 rules across
14 categories, compiled into a single-pass RegexSet DFA with a three-tier
fast-reject pipeline.

## Architecture

```
Hook JSON (stdin)
    │
    ▼
parse_reader<R: Read>()      ← hook.rs (testable, no stdin dependency)
    │
    ▼
extract_command()             ← Option<&str>
    │
    ▼
resolve_cached()              ← cache.rs (fingerprint-based invalidation)
    │
    ▼
RegexEngine<N, P>::check()   ← engine.rs (generic over Normalizer + Prefilter)
    ├─ N::normalize()         ← Cow<str> (zero-alloc when no nix path)
    ├─ P::is_safe()           ← zero-alloc prefix scan + byte-level SQL keyword check
    └─ RegexSet::matches()    ← single-pass DFA, early-exit on first Block
    │
    ▼
Decision { Allow | Block | Warn }
```

## Trait System

| Trait | Purpose | Production | Testing |
|-------|---------|-----------|---------|
| `Normalizer` | Command preprocessing (`Cow<str>`) | `NixStoreNormalizer` | `IdentityNormalizer` |
| `Prefilter` | Fast-reject safe commands | `PrefixPrefilter` | `NullPrefilter` |
| `RuleEngine` | Match commands against rules | `RegexEngine<N, P>` | (mock via `with_plugins`) |
| `RuleProvider` | Load rules from sources | `DefaultsProvider`, `DirectoryProvider` | `MockProvider` |
| `CacheStore` | Persist compiled rules | `FsCache` | `MemCache` |
| `Fingerprinter` | Detect config staleness | `FsFingerprinter` | `FixedFingerprinter` |

`RegexEngine` uses default type params — `RegexEngine::new(rules)` gives production
behavior; `RegexEngine::with_plugins(rules, IdentityNormalizer, NullPrefilter)` gives
full DFA testing without normalization or prefilter interference.

## Module Guide

| Module | Responsibility | Key types |
|--------|---------------|-----------|
| `model` | Data types, builder, Display impls | `Rule`, `RuleBuilder`, `Decision`, `Severity`, `Category` |
| `engine` | Matching pipeline, traits | `Normalizer`, `Prefilter`, `RuleEngine`, `RegexEngine` |
| `config` | Rule resolution, providers | `RuleProvider`, `DefaultsProvider`, `DirectoryProvider` |
| `cache` | Fingerprint-based caching | `CacheStore`, `Fingerprinter`, `CompiledCache` |
| `hook` | Claude Code JSON parsing | `HookInput`, `parse_reader`, `extract_command` |
| `dispatch` | `guardrail hook <EVENT>`: typed per-event actions from `hooks:` | `Action`, `ActionEntry`, `Outcome`, `Verdict`, `dispatch`, `validate` |
| `testing` | Auto-derived test validation | `validate_all_rules_regex`, `validate_all_rules_engine`, `benchmark_rules` |

## Rule Files

Embedded defaults + pluggable suites in `~/.config/guardrail/rules.d/`. This
repo holds only generic suites; a suite about one organisation lives in that
organisation's blackmatter-* repo and is contributed through
`blackmatter.components.claude.guardrail.ruleSuites` (akeyless suites in
blackmatter-akeyless, pleme-io doctrine in blackmatter-pleme).

| File | Rules | Source |
|------|-------|--------|
| `defaults.yaml` | 74 | Hand-written (compiled-in) |
| `sql.yaml` | 45 | Hand-written |
| `aws.yaml` | 26 | Hand-written |
| `azure.yaml` | 18 | Hand-written |
| `gcp.yaml` | 14 | Hand-written |
| `network.yaml` | 6 | Hand-written |
| `nosql.yaml` | 8 | Hand-written |
| `process.yaml` | 6 | Hand-written |
| `aws-generated.yaml` | ~2,200 | `guardrail-gen` from AWS SDK models |
| `prefilter.yaml` | data | commands, keywords and markers the prefilter routes to the engine |

Rule format:
```yaml
- name: rm-rf-root
  pattern: 'rm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/\s*$'
  severity: block
  message: "Recursive force-delete from root"
  category: filesystem
  test_block: "rm -rf /"       # optional: must match pattern
  test_allow: "rm -rf ./target" # optional: must NOT match pattern
  examples:                     # optional: more cases, same meaning
    block: ["rm -rf / --no-preserve-root"]
    allow: ["rm -rf build/"]
  window: team-production       # optional: allowed only inside an open change window with this tag
  tools: [Write, Edit]          # optional: exact tool names; unset = the tools check scans (Bash, Write, Edit, NotebookEdit, mcp__*)
  field: file_path              # optional: the tool_input field matched; unset = the fields check scans for the tool
  cwd: '/akeylesslabs/'         # optional: regex the hook payload's cwd must match
```

A rule with `tools`, `field` or `cwd` is scoped: it is matched on its own
(`src/scope.rs`), never through the prefilter, and only on calls its scope
names. An unscoped rule runs in the RegexSet behind the prefilter exactly as
before. A scoped rule's examples may be objects, `{input, tool, cwd}`, so the
call it applies to is part of the example; `validate` builds that call and runs
it. An MCP tool a scoped rule names is read only by the rules that name it:
its fields are prose (a PR body, a comment, a page), and the command rules would
refuse a runbook quoted in it. `validate --hooked-tools A,B` also fails any rule whose tool `guardrail
check` is not registered for.

Every config struct refuses an unknown key (`deny_unknown_fields`). The refusal
is scoped: an unknown or malformed top-level key of `guardrail.yaml`, or a rule
entry that does not parse in a suite or `extraRules`, is dropped on its own and
its siblings keep working; `validate` fails naming it. The run-time window file
envelope stays open (its writer adds metadata) and each window entry is strict
on its own.

`guardrail validate` runs every rule's block and allow examples and checks the
declared change windows; a failure exits non-zero.

Windows come from `changeWindows` in `guardrail.yaml` plus every file in
`changeWindowFiles` (absolute, or relative to `~/.config/guardrail/`), each a
`{changeWindows: [...]}` document written at run time by a sync job (for
example from approved tickets). The files are read on every windowed block; a
missing or unparseable file opens nothing and is named in the block message,
and an invalid entry never opens while its valid siblings do. `validate`
reports file problems without failing, since the files are run-time data.

## Categories

A category is any lowercase name (`[a-z0-9_-]+`) a suite chooses; the
`categories` map in `guardrail.yaml` turns one off (missing = on).

## CLI

```bash
guardrail check     # Read hook JSON from stdin, return decision
guardrail compile   # Pre-compile rules to ~/.cache/guardrail/compiled.json
guardrail validate  # Validate config + rules (--hooked-tools A,B to check hook registration)
guardrail list      # Show all active rules
guardrail schema    # Config keys this build accepts (--expect FILE fails on drift)
```

## User Config

`~/.config/guardrail/guardrail.yaml` (shikumi convention):
```yaml
categories:
  cloud: false          # disable entire category
disabledRules:
  - rm-rf-root          # disable specific rule
extraRules:
  - name: my-rule
    pattern: 'dangerous\s+command'
    severity: block
    message: "Custom guardrail"
    category: filesystem
```

## Performance

| Path | Time | Allocation |
|------|------|-----------|
| Safe command (prefilter) | ~50ns | Zero |
| Dangerous command (DFA) | ~1-5µs | Zero (Cow::Borrowed) |
| Cache hit | ~1ms | JSON deserialize |
| Full compile (2,468 rules) | ~300ms | RegexSet DFA |

## Testing

171 tests total. Every rule is validated:
- **Regex level**: auto-derived test command matches each pattern
- **Engine level**: test command produces Block/Warn through full pipeline
- **Performance**: compile time + per-rule match time benchmarked

`Rule::builder("name", "pattern").severity(Warn).build()` for test ergonomics.

## Deployment — the module trio owns the option types

The flake emits `homeManagerModules` / `nixosModules` / `darwinModules` from one
`module` spec through substrate's `rust.tool` (`module-trio.nix`). The binary
owns the types: `nix/types.nix` mirrors the Rust config 1:1 under
`blackmatter.components.claude.guardrail` (`hmNamespace`), `nix/render.nix`
renders it, `nix/hm.nix` deploys it. The system arms install the package only:
guardrail reads `~/.config/guardrail`, so a system-wide render would be read by
nothing.

| Option | Renders to |
|---|---|
| `enable`, `package` | `home.packages`, every hook command |
| `categories`, `extraRules`, `disabledRules`, `toolInputLimits`, `changeWindows`, `changeWindowFiles`, `prefilter`, `hooks.<Event>` | `guardrail.yaml`, 1:1 |
| `ruleSuites.<name>.{enable, source, rules}` | `rules.d/<name>.yaml` (a file, or typed rules; exactly one) |
| `hookEvents`, `checkTools`, `hookRegistrations` (read-only) | what blackmatter-claude registers in Claude Code settings |

On rebuild the rendered config and every suite run through `guardrail validate
--hooked-tools <checkTools>` in a derivation that IS the deployed payload, so a
failing example, an unknown key or a rule for an unhooked tool stops the
rebuild. `guardrail compile` runs at activation.

Parity tiers, per field: a misspelled or mistyped option is an eval error (the
module system; `categories` names via `addCheck`); an unknown YAML key is a Rust
parse refusal; a failing example or unhooked tool is a rebuild-time validate
failure. `nix flake check` adds the drift gate: `guardrail-module-roundtrip`
renders a fixture that must set every option (asserted), validates it, and runs
`guardrail schema --expect` against the option names, so a field on one side
only fails the build; three negative controls prove the refusals fire.

## Conventions

- Edition 2024, Rust 1.89.0+, MIT, clippy pedantic
- Release: `codegen-units=1, lto=true, opt-level="z", strip=true`
- All rules PUBLIC on GitHub
- Generated rules (`*-generated.yaml`) come from `guardrail-gen` — don't edit manually
