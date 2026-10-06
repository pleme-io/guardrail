use crate::hook::{HookInput, ToolInput};
use crate::model::ToolInputLimit;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitBreach {
    pub rule: String,
    pub message: String,
}

fn field_text<'a>(input: &'a ToolInput, field: &str) -> Option<&'a str> {
    let named = match field {
        "command" => input.command.as_deref(),
        "file_path" => input.file_path.as_deref(),
        "content" => input.content.as_deref(),
        "new_string" => input.new_string.as_deref(),
        "old_string" => input.old_string.as_deref(),
        "new_source" => input.new_source.as_deref(),
        "pattern" => input.pattern.as_deref(),
        "path" => input.path.as_deref(),
        "glob" => input.glob.as_deref(),
        "output_mode" => input.output_mode.as_deref(),
        _ => None,
    };
    named.or_else(|| input.extra.get(field).and_then(serde_json::Value::as_str))
}

#[must_use]
pub fn check(input: &HookInput, limits: &[ToolInputLimit]) -> Option<LimitBreach> {
    let tool = input.tool_name.as_deref()?;
    let tool_input = input.tool_input.as_ref()?;
    limits
        .iter()
        .filter(|l| l.tools.iter().any(|t| t == tool))
        .find_map(|l| {
            let count = field_text(tool_input, &l.field)?.chars().count();
            (count > l.max_chars).then(|| LimitBreach {
                rule: l.name.clone(),
                message: format!(
                    "{} ({count} characters; the limit is {})",
                    l.message, l.max_chars
                ),
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hook::parse_reader;

    fn limit(max: usize) -> ToolInputLimit {
        ToolInputLimit {
            name: "jira-comment-length".into(),
            tools: vec![
                "mcp__atlassian__jira_add_comment".into(),
                "mcp__atlassian__jira_edit_comment".into(),
            ],
            field: "body".into(),
            max_chars: max,
            message: "keep it short".into(),
        }
    }

    fn input(tool: &str, body: &str) -> HookInput {
        let json = serde_json::json!({"tool_name": tool, "tool_input": {"issue_key": "ASM-1", "body": body}});
        parse_reader(json.to_string().as_bytes()).unwrap()
    }

    #[test]
    fn blocks_a_listed_tool_over_the_limit() {
        let b = check(
            &input("mcp__atlassian__jira_add_comment", &"a".repeat(141)),
            &[limit(140)],
        )
        .unwrap();
        assert_eq!(b.rule, "jira-comment-length");
        assert!(
            b.message.contains("141 characters; the limit is 140"),
            "{}",
            b.message
        );
    }

    #[test]
    fn allows_exactly_the_limit() {
        assert_eq!(
            check(
                &input("mcp__atlassian__jira_edit_comment", &"a".repeat(140)),
                &[limit(140)]
            ),
            None
        );
    }

    #[test]
    fn counts_characters_not_bytes() {
        assert_eq!(
            check(
                &input("mcp__atlassian__jira_add_comment", &"é".repeat(140)),
                &[limit(140)]
            ),
            None
        );
    }

    #[test]
    fn ignores_tools_not_listed_and_missing_fields() {
        assert_eq!(
            check(
                &input("mcp__atlassian__confluence_add_comment", &"a".repeat(500)),
                &[limit(140)]
            ),
            None
        );
        let json = serde_json::json!({"tool_name": "mcp__atlassian__jira_add_comment", "tool_input": {"issue_key": "ASM-1"}});
        let no_body = parse_reader(json.to_string().as_bytes()).unwrap();
        assert_eq!(check(&no_body, &[limit(140)]), None);
    }

    #[test]
    fn reads_named_fields_too() {
        let l = ToolInputLimit {
            tools: vec!["Bash".into()],
            field: "command".into(),
            ..limit(5)
        };
        let json =
            serde_json::json!({"tool_name": "Bash", "tool_input": {"command": "echo hello"}});
        let i = parse_reader(json.to_string().as_bytes()).unwrap();
        assert!(check(&i, &[l]).is_some());
    }

    #[test]
    fn parses_from_the_config_shape() {
        let yaml = "toolInputLimits:\n  - name: jira-comment-length\n    tools: [mcp__atlassian__jira_add_comment]\n    field: body\n    maxChars: 140\n    message: keep it short\n";
        let cfg: crate::model::GuardrailConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.tool_input_limits.len(), 1);
        assert_eq!(cfg.tool_input_limits[0].max_chars, 140);
    }
}
