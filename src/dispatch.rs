use std::collections::BTreeMap;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::hook::HookInput;

const EVENTS_JSON: &str = include_str!("../hooks/events.json");

/// One Claude Code hook event and the payload field its matcher is tested against.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HookEvent {
    pub name: String,
    pub subject: Option<String>,
}

/// Every hook event this build knows, from `hooks/events.json`.
///
/// # Panics
///
/// Panics only if the compiled-in table is not valid JSON, which a unit test rules out.
#[must_use]
pub fn events() -> &'static [HookEvent] {
    static EVENTS: OnceLock<Vec<HookEvent>> = OnceLock::new();
    EVENTS.get_or_init(|| serde_json::from_str(EVENTS_JSON).expect("hooks/events.json"))
}

#[must_use]
pub fn event(name: &str) -> Option<&'static HookEvent> {
    events().iter().find(|e| e.name == name)
}

/// A guardrail behaviour that already exists as its own subcommand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Builtin {
    Check,
    InputLimit,
    SearchNudge,
    SearchAdvise,
    MintAdvise,
    GenLockTie,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "camelCase", deny_unknown_fields)]
pub enum Action {
    Check {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        matcher: Option<String>,
    },
    InputLimit {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        matcher: Option<String>,
    },
    SearchNudge {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        matcher: Option<String>,
    },
    SearchAdvise {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        matcher: Option<String>,
    },
    MintAdvise {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        matcher: Option<String>,
    },
    GenLockTie {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        matcher: Option<String>,
    },
    Exec {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        matcher: Option<String>,
        command: Vec<String>,
    },
}

impl Action {
    #[must_use]
    pub fn matcher(&self) -> Option<&str> {
        match self {
            Self::Check { matcher }
            | Self::InputLimit { matcher }
            | Self::SearchNudge { matcher }
            | Self::SearchAdvise { matcher }
            | Self::MintAdvise { matcher }
            | Self::GenLockTie { matcher }
            | Self::Exec { matcher, .. } => matcher.as_deref(),
        }
    }

    #[must_use]
    pub const fn builtin(&self) -> Option<Builtin> {
        match self {
            Self::Check { .. } => Some(Builtin::Check),
            Self::InputLimit { .. } => Some(Builtin::InputLimit),
            Self::SearchNudge { .. } => Some(Builtin::SearchNudge),
            Self::SearchAdvise { .. } => Some(Builtin::SearchAdvise),
            Self::MintAdvise { .. } => Some(Builtin::MintAdvise),
            Self::GenLockTie { .. } => Some(Builtin::GenLockTie),
            Self::Exec { .. } => None,
        }
    }
}

/// A configured action, or the raw entry when it does not parse.
///
/// Refusal is per entry: a malformed action is skipped at run time and named by
/// `guardrail validate`, while its siblings and the rest of guardrail.yaml keep working.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ActionEntry {
    Valid(Action),
    Invalid(serde_yaml::Value),
}

pub type HookTable = BTreeMap<String, Vec<ActionEntry>>;

#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Pass,
    Context(String),
    Json(Map<String, Value>),
    Block {
        rule: String,
        message: String,
    },
    Exit {
        code: i32,
        stdout: String,
        stderr: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    Silent,
    Print(String),
    Block {
        rule: String,
        message: String,
    },
    Exit {
        code: i32,
        stdout: String,
        stderr: String,
    },
}

pub trait Builtins {
    fn run(&self, builtin: Builtin, event: &str, input: &HookInput) -> Outcome;
}

fn is_simple(matcher: &str) -> bool {
    matcher
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '|')
}

/// Claude Code's matcher semantics: empty or `*` matches all, a plain `A|B` list
/// matches exact names, anything else is an unanchored regex.
#[must_use]
pub fn matches(matcher: Option<&str>, subject: Option<&str>) -> bool {
    let Some(m) = matcher.filter(|m| !m.is_empty() && *m != "*") else {
        return true;
    };
    let Some(s) = subject else {
        return false;
    };
    let base = s.rsplit('/').next().unwrap_or(s);
    if is_simple(m) {
        return m.split('|').any(|name| name == s || name == base);
    }
    Regex::new(m).is_ok_and(|re| re.is_match(s) || re.is_match(base))
}

fn subject<'a>(event: &HookEvent, payload: &'a Value) -> Option<&'a str> {
    event
        .subject
        .as_deref()
        .and_then(|field| payload.get(field))
        .and_then(Value::as_str)
}

fn is_terminal(json: &Map<String, Value>) -> bool {
    json.get("decision").and_then(Value::as_str) == Some("block")
        || json.get("continue").and_then(Value::as_bool) == Some(false)
        || json
            .get("hookSpecificOutput")
            .and_then(|h| h.get("permissionDecision"))
            .and_then(Value::as_str)
            == Some("deny")
}

fn merge(into: &mut Map<String, Value>, from: Map<String, Value>) {
    for (k, v) in from {
        match (into.get_mut(&k), v) {
            (Some(Value::Object(a)), Value::Object(b)) => merge(a, b),
            (_, v) => {
                into.insert(k, v);
            }
        }
    }
}

/// Run a configured command with the hook payload on stdin and read its decision.
///
/// Exit 0 passes stdout through (a JSON object is merged, plain text becomes
/// context), exit 2 is a blocking decision passed through verbatim, and any other
/// failure is reported on stderr without stopping the remaining actions.
#[must_use]
pub fn exec(command: &[String], raw: &str) -> Outcome {
    let Some((program, args)) = command.split_first() else {
        eprintln!("guardrail hook: exec action has an empty command");
        return Outcome::Pass;
    };
    let child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            eprintln!("guardrail hook: exec {program}: {e}");
            return Outcome::Pass;
        }
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(raw.as_bytes());
    }
    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("guardrail hook: exec {program}: {e}");
            return Outcome::Pass;
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    match output.status.code() {
        Some(0) => {
            let text = stdout.trim();
            if text.is_empty() {
                Outcome::Pass
            } else if let Ok(Value::Object(json)) = serde_json::from_str::<Value>(text) {
                Outcome::Json(json)
            } else {
                Outcome::Context(text.to_string())
            }
        }
        Some(2) => Outcome::Exit {
            code: 2,
            stdout,
            stderr,
        },
        code => {
            eprintln!(
                "guardrail hook: exec {program} exited {}: {}",
                code.map_or_else(|| "by signal".to_string(), |c| c.to_string()),
                stderr.trim()
            );
            Outcome::Pass
        }
    }
}

/// Dispatch one hook event through the configured actions, in order.
///
/// An event with no actions, or one this build does not know, is silent: no
/// output and exit 0, so an unconfigured or newer event never affects the session.
#[must_use]
pub fn dispatch(name: &str, raw: &str, table: &HookTable, builtins: &dyn Builtins) -> Verdict {
    let Some(entries) = table.get(name).filter(|e| !e.is_empty()) else {
        return Verdict::Silent;
    };
    let Some(event) = event(name) else {
        eprintln!("guardrail hook: unknown event {name}");
        return Verdict::Silent;
    };
    let payload: Value = serde_json::from_str(raw).unwrap_or(Value::Null);
    let input: HookInput = serde_json::from_value(payload.clone()).unwrap_or(HookInput {
        tool_name: None,
        tool_input: None,
        cwd: None,
    });
    let subject = subject(event, &payload);

    let mut json = Map::new();
    let mut context: Vec<String> = Vec::new();
    for entry in entries {
        let ActionEntry::Valid(action) = entry else {
            eprintln!("guardrail hook: skipping an invalid {name} action (run guardrail validate)");
            continue;
        };
        if !matches(action.matcher(), subject) {
            continue;
        }
        let outcome = match (action.builtin(), action) {
            (Some(b), _) => builtins.run(b, name, &input),
            (None, Action::Exec { command, .. }) => exec(command, raw),
            (None, _) => Outcome::Pass,
        };
        match outcome {
            Outcome::Pass => {}
            Outcome::Context(c) => context.push(c),
            Outcome::Json(j) => {
                let stop = is_terminal(&j);
                merge(&mut json, j);
                if stop {
                    break;
                }
            }
            Outcome::Block { rule, message } => return Verdict::Block { rule, message },
            Outcome::Exit {
                code,
                stdout,
                stderr,
            } => {
                return Verdict::Exit {
                    code,
                    stdout,
                    stderr,
                };
            }
        }
    }
    render(name, json, &context)
}

fn render(name: &str, mut json: Map<String, Value>, context: &[String]) -> Verdict {
    if !context.is_empty() {
        let hso = json
            .entry("hookSpecificOutput")
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(h) = hso {
            h.insert("hookEventName".into(), Value::String(name.into()));
            let prior = h
                .get("additionalContext")
                .and_then(Value::as_str)
                .map(str::to_string);
            let joined = prior
                .into_iter()
                .chain(context.iter().cloned())
                .collect::<Vec<_>>()
                .join("\n\n");
            h.insert("additionalContext".into(), Value::String(joined));
        }
    }
    if json.is_empty() {
        Verdict::Silent
    } else {
        Verdict::Print(Value::Object(json).to_string())
    }
}

/// Every problem in a hook table, one line per refused entry.
#[must_use]
pub fn validate(table: &HookTable) -> Vec<String> {
    let mut failures = Vec::new();
    for (name, entries) in table {
        let Some(event) = event(name) else {
            failures.push(format!("hooks.{name}: unknown hook event"));
            continue;
        };
        for (i, entry) in entries.iter().enumerate() {
            let at = format!("hooks.{name}[{i}]");
            let action = match entry {
                ActionEntry::Valid(a) => a,
                ActionEntry::Invalid(raw) => {
                    failures.push(format!(
                        "{at}: not a valid action (one of check, inputLimit, searchNudge, searchAdvise, mintAdvise, genLockTie, exec with a command): {}",
                        serde_json::to_string(raw).unwrap_or_default()
                    ));
                    continue;
                }
            };
            if matches!(action, Action::Exec { command, .. } if command.is_empty()) {
                failures.push(format!("{at}: exec needs a non-empty command"));
            }
            if let Some(m) = action.matcher().filter(|m| !m.is_empty() && *m != "*") {
                if event.subject.is_none() {
                    failures.push(format!("{at}: {name} takes no matcher"));
                } else if !is_simple(m)
                    && let Err(e) = Regex::new(m)
                {
                    failures.push(format!("{at}: matcher is not a valid regex: {e}"));
                }
            }
        }
    }
    failures
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct Recorder {
        calls: RefCell<Vec<(Builtin, String)>>,
        reply: Box<dyn Fn(Builtin) -> Outcome>,
    }

    impl Recorder {
        fn new(reply: impl Fn(Builtin) -> Outcome + 'static) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                reply: Box::new(reply),
            }
        }
    }

    impl Builtins for Recorder {
        fn run(&self, builtin: Builtin, event: &str, _input: &HookInput) -> Outcome {
            self.calls.borrow_mut().push((builtin, event.to_string()));
            (self.reply)(builtin)
        }
    }

    fn table(yaml: &str) -> HookTable {
        serde_yaml::from_str(yaml).unwrap()
    }

    const BASH: &str =
        r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}"#;
    const GREP: &str =
        r#"{"hook_event_name":"PostToolUse","tool_name":"Grep","tool_input":{"pattern":"x"}}"#;

    #[test]
    fn the_event_table_parses_and_names_are_unique() {
        let names: std::collections::BTreeSet<_> = events().iter().map(|e| &e.name).collect();
        assert_eq!(names.len(), events().len());
        for required in [
            "PreToolUse",
            "PostToolUse",
            "UserPromptSubmit",
            "Notification",
            "Stop",
            "SubagentStop",
            "PreCompact",
            "SessionStart",
            "SessionEnd",
        ] {
            assert!(event(required).is_some(), "{required} missing");
        }
    }

    #[test]
    fn an_event_with_no_actions_is_silent_and_runs_nothing() {
        let rec = Recorder::new(|_| Outcome::Context("x".into()));
        assert_eq!(
            dispatch("Stop", "{}", &HookTable::new(), &rec),
            Verdict::Silent
        );
        let empty = table("Stop: []");
        assert_eq!(dispatch("Stop", "{}", &empty, &rec), Verdict::Silent);
        assert!(rec.calls.borrow().is_empty());
    }

    #[test]
    fn an_unknown_event_is_silent_even_when_configured() {
        let rec = Recorder::new(|_| Outcome::Context("x".into()));
        let t = table("NoSuchEvent:\n  - action: check");
        assert_eq!(dispatch("NoSuchEvent", "{}", &t, &rec), Verdict::Silent);
        assert!(rec.calls.borrow().is_empty());
        assert_eq!(
            validate(&t),
            vec!["hooks.NoSuchEvent: unknown hook event".to_string()]
        );
    }

    #[test]
    fn each_builtin_action_routes_to_its_builtin() {
        for (name, builtin) in [
            ("check", Builtin::Check),
            ("inputLimit", Builtin::InputLimit),
            ("searchNudge", Builtin::SearchNudge),
            ("searchAdvise", Builtin::SearchAdvise),
            ("mintAdvise", Builtin::MintAdvise),
            ("genLockTie", Builtin::GenLockTie),
        ] {
            let rec = Recorder::new(|_| Outcome::Pass);
            let t = table(&format!("PreToolUse:\n  - action: {name}"));
            assert!(validate(&t).is_empty());
            assert_eq!(dispatch("PreToolUse", BASH, &t, &rec), Verdict::Silent);
            assert_eq!(
                *rec.calls.borrow(),
                vec![(builtin, "PreToolUse".to_string())]
            );
        }
    }

    #[test]
    fn a_matcher_scopes_an_action_to_its_subject() {
        let rec = Recorder::new(|_| Outcome::Pass);
        let t = table(
            "PreToolUse:\n  - action: check\n    matcher: Bash\n  - action: searchNudge\n    matcher: Grep|Glob",
        );
        let _ = dispatch("PreToolUse", BASH, &t, &rec);
        assert_eq!(rec.calls.borrow().len(), 1);
        assert_eq!(rec.calls.borrow()[0].0, Builtin::Check);
        assert!(matches(
            Some("mcp__.*"),
            Some("mcp__atlassian__jira_add_comment")
        ));
        assert!(!matches(Some("Bash"), Some("BashOutput")));
        assert!(matches(Some("*"), None));
        assert!(!matches(Some("Bash"), None));
    }

    #[test]
    fn a_block_is_terminal_and_skips_later_actions() {
        let rec = Recorder::new(|b| match b {
            Builtin::Check => Outcome::Block {
                rule: "r".into(),
                message: "m".into(),
            },
            _ => Outcome::Context("later".into()),
        });
        let t = table("PreToolUse:\n  - action: check\n  - action: searchAdvise");
        assert_eq!(
            dispatch("PreToolUse", BASH, &t, &rec),
            Verdict::Block {
                rule: "r".into(),
                message: "m".into()
            }
        );
        assert_eq!(rec.calls.borrow().len(), 1);
    }

    #[test]
    fn context_renders_as_additional_context_for_the_event() {
        let rec = Recorder::new(|b| match b {
            Builtin::SearchAdvise => Outcome::Context("one".into()),
            _ => Outcome::Context("two".into()),
        });
        let t = table("PostToolUse:\n  - action: searchAdvise\n  - action: mintAdvise");
        let Verdict::Print(out) = dispatch("PostToolUse", GREP, &t, &rec) else {
            panic!("expected output");
        };
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PostToolUse");
        assert_eq!(v["hookSpecificOutput"]["additionalContext"], "one\n\ntwo");
    }

    #[test]
    fn a_single_context_matches_the_standalone_subcommand_shape() {
        let rec = Recorder::new(|_| Outcome::Context("msg".into()));
        let t = table("PostToolUse:\n  - action: searchAdvise");
        let Verdict::Print(out) = dispatch("PostToolUse", GREP, &t, &rec) else {
            panic!("expected output");
        };
        let expected = serde_json::json!({
            "hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": "msg"}
        });
        assert_eq!(serde_json::from_str::<Value>(&out).unwrap(), expected);
    }

    #[test]
    fn exec_passes_a_json_decision_through() {
        let rec = Recorder::new(|_| Outcome::Pass);
        let t = table(
            r#"Stop:
  - action: exec
    command: [sh, -c, "cat >/dev/null; printf '%s' '{\"decision\":\"block\",\"reason\":\"no\"}'"]
  - action: check"#,
        );
        let Verdict::Print(out) = dispatch("Stop", "{}", &t, &rec) else {
            panic!("expected output");
        };
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["decision"], "block");
        assert!(
            rec.calls.borrow().is_empty(),
            "a block decision is terminal"
        );
    }

    #[test]
    fn exec_receives_the_payload_on_stdin() {
        let rec = Recorder::new(|_| Outcome::Pass);
        let t = table("UserPromptSubmit:\n  - action: exec\n    command: [cat]");
        let raw = r#"{"hook_event_name":"UserPromptSubmit","prompt":"hi"}"#;
        let Verdict::Print(out) = dispatch("UserPromptSubmit", raw, &t, &rec) else {
            panic!("expected output");
        };
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["prompt"], "hi");
    }

    #[test]
    fn exec_plain_text_becomes_context_and_exit_two_blocks() {
        let rec = Recorder::new(|_| Outcome::Pass);
        let t = table("SessionStart:\n  - action: exec\n    command: [sh, -c, 'echo hello']");
        let Verdict::Print(out) = dispatch("SessionStart", "{}", &t, &rec) else {
            panic!("expected output");
        };
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["hookSpecificOutput"]["additionalContext"], "hello");

        let t =
            table("PreToolUse:\n  - action: exec\n    command: [sh, -c, 'echo nope >&2; exit 2']");
        let Verdict::Exit { code, stderr, .. } = dispatch("PreToolUse", BASH, &t, &rec) else {
            panic!("expected exit");
        };
        assert_eq!(code, 2);
        assert_eq!(stderr.trim(), "nope");
    }

    #[test]
    fn exec_failure_is_not_blocking() {
        let rec = Recorder::new(|_| Outcome::Context("after".into()));
        let t = table(
            "PostToolUse:\n  - action: exec\n    command: [sh, -c, 'exit 1']\n  - action: exec\n    command: [/nonexistent/binary]\n  - action: mintAdvise",
        );
        let Verdict::Print(out) = dispatch("PostToolUse", GREP, &t, &rec) else {
            panic!("expected output");
        };
        assert!(out.contains("after"));
    }

    #[test]
    fn an_invalid_entry_is_refused_alone() {
        let rec = Recorder::new(|_| Outcome::Context("ok".into()));
        let t = table(
            "PostToolUse:\n  - action: frobnicate\n  - action: exec\n  - action: searchAdvise\nStop:\n  - action: check\n    matcher: x",
        );
        let failures = validate(&t);
        assert_eq!(failures.len(), 3, "{failures:?}");
        assert!(failures[0].contains("hooks.PostToolUse[0]"));
        assert!(failures[1].contains("hooks.PostToolUse[1]"));
        assert!(failures[2].contains("Stop takes no matcher"));
        let Verdict::Print(out) = dispatch("PostToolUse", GREP, &t, &rec) else {
            panic!("the valid sibling still runs");
        };
        assert!(out.contains("ok"));
    }

    #[test]
    fn a_bad_regex_matcher_is_refused() {
        let t = table("PreToolUse:\n  - action: check\n    matcher: '(['");
        assert_eq!(validate(&t).len(), 1);
    }
}
