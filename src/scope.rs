//! Rules scoped by tool, `tool_input` field or working directory.
//!
//! An unscoped rule runs in the `RegexSet` behind the prefilter, over the text
//! `check` extracts from Bash, Write, Edit, `NotebookEdit` and MCP calls. A
//! scoped rule names the tools it applies to (`tools`, exact names), the field
//! its pattern reads (`field`), or a regex the payload's `cwd` must match
//! (`cwd`). Scoped rules are few, so each is matched on its own and none passes
//! through the prefilter: the scope already says which calls it reads.

use hayai::engine::{ChainedNormalizer, Normalizer, PathNormalizer};
use regex::Regex;

use crate::engine::{ProductionNormalizer, SqlCommentStripper};
use crate::hook::{self, HookInput};
use crate::model::{Decision, Example, Rule, Severity};

/// Whether `check` extracts text from this tool's input when a rule names no field.
#[must_use]
pub fn scanned_without_field(tool: &str) -> bool {
    matches!(tool, "Bash" | "Write" | "Edit" | "NotebookEdit") || tool.starts_with("mcp__")
}

/// The field a rule with no `field` reads for this tool, as an example is built for it.
#[must_use]
pub fn default_field(tool: &str) -> Option<&'static str> {
    match tool {
        "Bash" => Some("command"),
        "Write" => Some("content"),
        "Edit" => Some("new_string"),
        "NotebookEdit" => Some("new_source"),
        t if t.starts_with("mcp__") => Some("input"),
        _ => None,
    }
}

struct Compiled {
    rule: Rule,
    pattern: Regex,
    cwd: Option<Regex>,
}

pub struct ScopedRules {
    rules: Vec<Compiled>,
    normalizer: ProductionNormalizer,
}

impl std::fmt::Debug for ScopedRules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScopedRules")
            .field("rule_count", &self.rules.len())
            .finish_non_exhaustive()
    }
}

impl ScopedRules {
    /// The scoped rules among `rules`, and each one refused with why (an invalid
    /// `pattern` or `cwd` regex). A refused rule is left out on its own.
    #[must_use]
    pub fn new(rules: &[Rule]) -> (Self, Vec<String>) {
        let mut compiled = Vec::new();
        let mut problems = Vec::new();
        for rule in rules.iter().filter(|r| r.is_scoped()) {
            let pattern = match Regex::new(&rule.pattern) {
                Ok(p) => p,
                Err(e) => {
                    problems.push(format!("{}: pattern: {e}", rule.name));
                    continue;
                }
            };
            let cwd = match rule.cwd.as_deref().map(Regex::new).transpose() {
                Ok(c) => c,
                Err(e) => {
                    problems.push(format!("{}: cwd: {e}", rule.name));
                    continue;
                }
            };
            compiled.push(Compiled {
                rule: rule.clone(),
                pattern,
                cwd,
            });
        }
        (
            Self {
                rules: compiled,
                normalizer: ChainedNormalizer {
                    first: PathNormalizer,
                    second: SqlCommentStripper,
                },
            },
            problems,
        )
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    #[must_use]
    pub fn rule(&self, name: &str) -> Option<&Rule> {
        self.rules.iter().map(|c| &c.rule).find(|r| r.name == name)
    }

    /// The first blocking scoped rule this call matches, else the first warning, else allow.
    pub fn check(&self, input: &HookInput) -> Decision {
        let mut warn = None;
        for c in &self.rules {
            for (text, downgrade) in self.texts(c, input) {
                if !c.pattern.is_match(&text) {
                    continue;
                }
                if c.rule.severity == Severity::Block && !downgrade {
                    return Decision::from_rule(&c.rule);
                }
                if warn.is_none() {
                    warn = Some(Decision::Warn {
                        rule: c.rule.name.clone(),
                        message: c.rule.message.clone(),
                    });
                }
            }
        }
        warn.unwrap_or(Decision::Allow)
    }

    fn texts(&self, c: &Compiled, input: &HookInput) -> Vec<(String, bool)> {
        let tool = input.tool_name.as_deref().unwrap_or("");
        if !c.rule.tools.is_empty() && !c.rule.tools.iter().any(|t| t == tool) {
            return Vec::new();
        }
        if let Some(re) = &c.cwd
            && !input.cwd.as_deref().is_some_and(|d| re.is_match(d))
        {
            return Vec::new();
        }
        let Some(ti) = &input.tool_input else {
            return Vec::new();
        };
        if let Some(field) = &c.rule.field {
            let command = field == "command";
            return ti
                .field_texts(field)
                .into_iter()
                .map(|t| (self.normalized(&t, command), false))
                .collect();
        }
        let mut out = Vec::new();
        for item in hook::extract_scannable_content(input) {
            if item.context.is_content() {
                out.extend(
                    item.text
                        .lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("//"))
                        .map(|l| (l.to_owned(), true)),
                );
            } else {
                out.push((self.normalized(&item.text, true), false));
            }
        }
        out
    }

    fn normalized(&self, text: &str, command: bool) -> String {
        if command {
            self.normalizer.normalize(text).into_owned()
        } else {
            text.to_owned()
        }
    }
}

/// Each of the rule's examples that does not do what it says, named with why.
#[must_use]
pub fn example_failures(rule: &Rule, prefilter: &crate::engine::PrefixPrefilter) -> Vec<String> {
    let block = rule
        .test_block
        .iter()
        .map(|t| Example::Text(t.clone()))
        .chain(rule.examples.block.iter().cloned());
    let allow = rule
        .test_allow
        .iter()
        .map(|t| Example::Text(t.clone()))
        .chain(rule.examples.allow.iter().cloned());
    let cases: Vec<(Example, bool)> = block
        .map(|e| (e, true))
        .chain(allow.map(|e| (e, false)))
        .collect();
    if rule.is_scoped() {
        return scoped_example_failures(rule, cases);
    }
    let single =
        match crate::engine::RegexEngine::with_prefilter(vec![rule.clone()], prefilter.clone()) {
            Ok(e) => e,
            Err(e) => return vec![format!("{}: pattern: {e}", rule.name)],
        };
    let mut failures = Vec::new();
    for (example, blocks) in cases {
        if example.tool().is_some() || example.cwd().is_some() {
            failures.push(format!(
                "{}: example names a tool or cwd but the rule has no tools, field or cwd: {}",
                rule.name,
                describe(&example)
            ));
            continue;
        }
        let allowed = crate::RuleEngine::check(&single, example.input()).is_allowed();
        if let Some(f) = verdict(rule, &example, blocks, allowed) {
            failures.push(f);
        }
    }
    failures
}

fn scoped_example_failures(rule: &Rule, cases: Vec<(Example, bool)>) -> Vec<String> {
    let mut failures: Vec<String> = rule
        .tools
        .iter()
        .filter(|t| rule.field.is_none() && !scanned_without_field(t))
        .map(|t| {
            format!(
                "{}: tool {t} has no field `check` scans; set `field`",
                rule.name
            )
        })
        .collect();
    let (scoped, problems) = ScopedRules::new(std::slice::from_ref(rule));
    failures.extend(problems);
    if scoped.is_empty() {
        return failures;
    }
    for (example, blocks) in cases {
        match example_call(rule, &example) {
            Ok(input) => {
                let allowed = scoped.check(&input).is_allowed();
                failures.extend(verdict(rule, &example, blocks, allowed));
            }
            Err(why) => failures.push(format!("{}: {why}: {}", rule.name, describe(&example))),
        }
    }
    failures
}

fn verdict(rule: &Rule, example: &Example, blocks: bool, allowed: bool) -> Option<String> {
    if blocks && allowed {
        Some(format!(
            "{}: block example does not match: {}",
            rule.name,
            describe(example)
        ))
    } else if !blocks && !allowed {
        Some(format!(
            "{}: allow example matches: {}",
            rule.name,
            describe(example)
        ))
    } else {
        None
    }
}

fn describe(e: &Example) -> String {
    match (e.tool(), e.cwd()) {
        (None, None) => e.input().to_owned(),
        (t, c) => format!(
            "{} (tool {}, cwd {})",
            e.input(),
            t.unwrap_or("-"),
            c.unwrap_or("-")
        ),
    }
}

/// The hook call an example stands for: its tool (or the rule's first, or Bash), its cwd,
/// and its input in the rule's field (or the field `check` scans for that tool).
///
/// # Errors
///
/// The tool has no field `check` scans and the rule names none.
pub fn example_call(rule: &Rule, example: &Example) -> Result<HookInput, String> {
    let tool = example
        .tool()
        .or_else(|| rule.tools.first().map(String::as_str))
        .unwrap_or("Bash");
    let field = rule
        .field
        .as_deref()
        .or_else(|| default_field(tool))
        .ok_or_else(|| format!("tool {tool} has no field `check` scans"))?;
    let mut tool_input = serde_json::Map::new();
    tool_input.insert(field.to_owned(), example.input().into());
    serde_json::from_value(serde_json::json!({
        "tool_name": tool,
        "cwd": example.cwd(),
        "tool_input": tool_input,
    }))
    .map_err(|e| e.to_string())
}

/// Each rule tool for which `guardrail check` is not registered, so the rule could never run.
#[must_use]
pub fn unhooked(rules: &[Rule], hooked: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for r in rules {
        let tools: Vec<&str> = if r.tools.is_empty() {
            vec!["Bash"]
        } else {
            r.tools.iter().map(String::as_str).collect()
        };
        for t in tools {
            if !hooked.iter().any(|h| h == t) {
                out.push(format!(
                    "{}: `guardrail check` is not registered for tool {t}, so the rule never runs",
                    r.name
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Category, ExampleCall};

    #[test]
    fn scoped_examples_carry_their_tool_and_cwd() {
        let mut rule = Rule::builder("akl-force-push", r"git\s+push\b.*(--force|\s-f\b)")
            .cwd("/akeylesslabs/")
            .build();
        let at = |input: &str, cwd: &str| {
            Example::Call(ExampleCall {
                input: input.into(),
                tool: None,
                cwd: Some(cwd.into()),
            })
        };
        rule.examples
            .block
            .push(at("git push -f", "/c/akeylesslabs/r"));
        rule.examples.allow.push(at("git push -f", "/c/pleme-io/r"));
        rule.examples
            .allow
            .push(at("git push", "/c/akeylesslabs/r"));
        let pf = crate::engine::PrefixPrefilter::default();
        assert!(example_failures(&rule, &pf).is_empty());
        rule.examples.block.push(at("git push -f", "/c/pleme-io/r"));
        assert_eq!(example_failures(&rule, &pf).len(), 1);
    }

    #[test]
    fn a_tool_without_a_scanned_field_must_name_one() {
        let rule = Rule::builder("read-secret", "secret")
            .tools(["Read"])
            .build();
        let pf = crate::engine::PrefixPrefilter::default();
        assert!(example_failures(&rule, &pf)[0].contains("set `field`"));
    }

    #[test]
    fn an_unscoped_example_may_not_name_a_tool() {
        let mut rule = Rule::builder("rm", r"rm\s+-rf\s+/$").build();
        rule.examples.block.push(Example::Call(ExampleCall {
            input: "rm -rf /".into(),
            tool: Some("Bash".into()),
            cwd: None,
        }));
        let pf = crate::engine::PrefixPrefilter::default();
        assert!(example_failures(&rule, &pf)[0].contains("no tools, field or cwd"));
    }

    #[test]
    fn a_rule_for_an_unhooked_tool_is_named() {
        let rules = [Rule::builder("w", "x")
            .tools(["Write"])
            .field("file_path")
            .build()];
        assert_eq!(unhooked(&rules, &["Bash".into()]).len(), 1);
        assert!(unhooked(&rules, &["Bash".into(), "Write".into()]).is_empty());
    }

    #[allow(clippy::needless_pass_by_value)]
    fn call(tool: &str, cwd: Option<&str>, input: serde_json::Value) -> HookInput {
        serde_json::from_value(serde_json::json!({
            "tool_name": tool,
            "cwd": cwd,
            "tool_input": input,
        }))
        .unwrap()
    }

    fn one(rule: Rule) -> ScopedRules {
        let (s, problems) = ScopedRules::new(&[rule]);
        assert!(problems.is_empty(), "{problems:?}");
        s
    }

    fn force_push() -> Rule {
        Rule::builder("akl-force-push", r"git\s+push\b.*(--force|\s-f\b)")
            .message("no force push in akeylesslabs")
            .category(Category::try_from("git".to_owned()).unwrap())
            .cwd("/akeylesslabs/")
            .build()
    }

    #[test]
    fn a_cwd_scoped_rule_applies_only_under_its_cwd() {
        let s = one(force_push());
        let push = serde_json::json!({"command": "git push -f origin feat"});
        assert!(
            s.check(&call(
                "Bash",
                Some("/Users/x/code/github/akeylesslabs/repo"),
                push.clone()
            ))
            .is_blocked()
        );
        assert!(
            s.check(&call(
                "Bash",
                Some("/Users/x/code/github/pleme-io/repo"),
                push.clone()
            ))
            .is_allowed()
        );
        assert!(s.check(&call("Bash", None, push)).is_allowed());
    }

    #[test]
    fn a_tool_and_field_scoped_rule_reads_only_that_field_of_those_tools() {
        let s = one(Rule::builder(
            "claude-files",
            r"^/Users/[^/]+/\.claude/(skills|CLAUDE\.md|settings\.json)",
        )
        .tools(["Write", "Edit"])
        .field("file_path")
        .build());
        let path = "/Users/x/.claude/settings.json";
        assert!(
            s.check(&call(
                "Write",
                None,
                serde_json::json!({"file_path": path, "content": "{}"})
            ))
            .is_blocked()
        );
        assert!(
            s.check(&call("Edit", None, serde_json::json!({"file_path": path})))
                .is_blocked()
        );
        assert!(
            s.check(&call("Read", None, serde_json::json!({"file_path": path})))
                .is_allowed()
        );
        assert!(
            s.check(&call(
                "Write",
                None,
                serde_json::json!({"file_path": "/tmp/x", "content": path})
            ))
            .is_allowed()
        );
    }

    #[test]
    fn an_mcp_body_rule_reads_the_body_field() {
        let s = one(Rule::builder(
            "ai-trailer",
            r"(?i)co-authored-by:\s*claude|generated with \[?claude",
        )
        .tools([
            "mcp__github__create_pull_request",
            "mcp__github__update_pull_request",
        ])
        .field("body")
        .build());
        let body = serde_json::json!({"title": "x", "body": "fix\n\nCo-Authored-By: Claude <noreply@anthropic.com>"});
        assert!(
            s.check(&call(
                "mcp__github__create_pull_request",
                None,
                body.clone()
            ))
            .is_blocked()
        );
        assert!(
            s.check(&call("mcp__github__add_issue_comment", None, body))
                .is_allowed()
        );
        let title_only = serde_json::json!({"title": "Generated with Claude", "body": "fix"});
        assert!(
            s.check(&call("mcp__github__update_pull_request", None, title_only))
                .is_allowed()
        );
    }

    #[test]
    fn content_matches_without_a_field_are_downgraded_like_the_scanner() {
        let s = one(Rule::builder("drop", r"DROP\s+TABLE").cwd(".*").build());
        let d = s.check(&call(
            "Write",
            Some("/x"),
            serde_json::json!({"file_path": "/x/a.sql", "content": "DROP TABLE t;"}),
        ));
        assert!(matches!(d, Decision::Warn { .. }), "{d}");
    }

    #[test]
    fn an_invalid_cwd_regex_refuses_that_rule_alone() {
        let bad = Rule::builder("bad", "x").cwd("(").build();
        let (s, problems) = ScopedRules::new(&[bad, force_push()]);
        assert_eq!(problems.len(), 1);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn unscoped_rules_are_not_taken() {
        let (s, _) = ScopedRules::new(&[Rule::builder("plain", "x")
            .example_block(Example::from("x"))
            .build()]);
        assert!(s.is_empty());
    }
}
