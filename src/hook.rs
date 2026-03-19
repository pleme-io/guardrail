use std::collections::HashMap;

use serde::Deserialize;

/// Claude Code PreToolUse hook payload.
#[derive(Debug, Clone, Deserialize)]
pub struct HookInput {
    pub tool_name: Option<String>,
    pub tool_input: Option<ToolInput>,
}

/// Tool input fields — captures Bash, Write, Edit, NotebookEdit, and MCP tools.
#[derive(Debug, Clone, Deserialize)]
pub struct ToolInput {
    /// Bash command string.
    pub command: Option<String>,
    /// Write/Edit file path.
    pub file_path: Option<String>,
    /// Write tool: full file content.
    pub content: Option<String>,
    /// Edit tool: replacement string.
    pub new_string: Option<String>,
    /// Edit tool: string being replaced.
    pub old_string: Option<String>,
    /// NotebookEdit tool: new cell source.
    pub new_source: Option<String>,
    /// Catch-all for MCP tool parameters and other unknown fields.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// What kind of content is being scanned — determines severity behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanContext {
    /// Shell command — Block decisions enforced.
    BashCommand,
    /// File being written — downgraded to Warn (files may legitimately contain SQL etc).
    WriteContent,
    /// Edit replacement string — downgraded to Warn.
    EditNewString,
    /// Notebook cell source — downgraded to Warn.
    NotebookCell,
    /// MCP tool string parameter — Block decisions enforced.
    McpCommand,
}

impl ScanContext {
    /// Whether Block decisions should be downgraded to Warn for this context.
    #[must_use]
    pub const fn downgrade_block(&self) -> bool {
        matches!(
            self,
            Self::WriteContent | Self::EditNewString | Self::NotebookCell
        )
    }
}

/// A piece of scannable content extracted from a hook input.
#[derive(Debug, Clone)]
pub struct ScannableContent {
    pub context: ScanContext,
    pub text: String,
}

/// Extract all scannable content from a hook input.
///
/// Returns an empty Vec for tools with nothing to scan (Read, Glob, etc.).
#[must_use]
pub fn extract_scannable_content(input: &HookInput) -> Vec<ScannableContent> {
    let mut items = Vec::new();
    let tool_name = input.tool_name.as_deref().unwrap_or("");
    let tool_input = match &input.tool_input {
        Some(ti) => ti,
        None => return items,
    };

    match tool_name {
        "Bash" => {
            if let Some(cmd) = &tool_input.command {
                items.push(ScannableContent {
                    context: ScanContext::BashCommand,
                    text: cmd.clone(),
                });
            }
        }
        "Write" => {
            if let Some(content) = &tool_input.content {
                items.push(ScannableContent {
                    context: ScanContext::WriteContent,
                    text: content.clone(),
                });
            }
        }
        "Edit" => {
            if let Some(new_str) = &tool_input.new_string {
                items.push(ScannableContent {
                    context: ScanContext::EditNewString,
                    text: new_str.clone(),
                });
            }
        }
        "NotebookEdit" => {
            if let Some(src) = &tool_input.new_source {
                items.push(ScannableContent {
                    context: ScanContext::NotebookCell,
                    text: src.clone(),
                });
            }
        }
        _ if tool_name.starts_with("mcp__") => {
            // MCP tools: recursively collect all string values from extra fields
            collect_mcp_strings(&tool_input.extra, &mut items);
            // Also check known fields
            if let Some(cmd) = &tool_input.command {
                items.push(ScannableContent {
                    context: ScanContext::McpCommand,
                    text: cmd.clone(),
                });
            }
        }
        _ => {}
    }

    items
}

/// Maximum recursion depth for MCP JSON parameter collection.
/// Prevents pathological nesting from consuming stack/time.
const MCP_JSON_MAX_DEPTH: usize = 8;

/// Maximum number of strings to collect from MCP parameters.
/// Prevents extreme fan-out from slowing down the check.
const MCP_JSON_MAX_STRINGS: usize = 50;

/// Recursively collect string values from MCP tool parameters.
fn collect_mcp_strings(map: &HashMap<String, serde_json::Value>, items: &mut Vec<ScannableContent>) {
    for value in map.values() {
        if items.len() >= MCP_JSON_MAX_STRINGS {
            break;
        }
        collect_json_strings(value, items, 0);
    }
}

/// Recursively extract string values from a JSON value tree.
/// Bounded by depth and total item count for performance.
fn collect_json_strings(value: &serde_json::Value, items: &mut Vec<ScannableContent>, depth: usize) {
    if depth >= MCP_JSON_MAX_DEPTH || items.len() >= MCP_JSON_MAX_STRINGS {
        return;
    }
    match value {
        serde_json::Value::String(s) => {
            if !s.is_empty() {
                items.push(ScannableContent {
                    context: ScanContext::McpCommand,
                    text: s.clone(),
                });
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                collect_json_strings(v, items, depth + 1);
            }
        }
        serde_json::Value::Object(obj) => {
            for v in obj.values() {
                collect_json_strings(v, items, depth + 1);
            }
        }
        _ => {}
    }
}

/// Extract the command string from a hook input (legacy convenience).
#[must_use]
pub fn extract_command(input: &HookInput) -> Option<&str> {
    input.tool_input.as_ref()?.command.as_deref()
}

/// Parse hook JSON from any reader (testable without stdin).
///
/// # Errors
///
/// Returns an error if the reader fails or the JSON is invalid.
pub fn parse_reader<R: std::io::Read>(reader: R) -> anyhow::Result<HookInput> {
    let input = std::io::read_to_string(reader)?;
    Ok(serde_json::from_str(&input)?)
}

/// Parse hook JSON from stdin. Delegates to `parse_reader`.
///
/// # Errors
///
/// Returns an error if stdin can't be read or parsed.
pub fn parse_stdin() -> anyhow::Result<HookInput> {
    parse_reader(std::io::stdin())
}

/// Scan multi-line content (Write/Edit) line by line, skipping blanks and comments.
/// Returns lines that look like they could contain dangerous patterns.
///
/// Performance: uses the prefilter to skip obviously safe lines, avoiding
/// unnecessary String allocations. Only lines that pass the prefilter (i.e.,
/// might be dangerous) are returned.
#[must_use]
pub fn scan_content_lines(content: &str) -> Vec<String> {
    use crate::engine::{PrefixPrefilter, Prefilter};
    let prefilter = PrefixPrefilter;
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with('#') && !line.starts_with("//"))
        .filter(|line| !prefilter.is_safe(line))
        .map(String::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bash_hook() {
        let json = r#"{"tool_name": "Bash", "tool_input": {"command": "ls -la"}}"#;
        let input = parse_reader(json.as_bytes()).unwrap();
        assert_eq!(extract_command(&input), Some("ls -la"));
    }

    #[test]
    fn parse_missing_command() {
        let json = r#"{"tool_name": "Write", "tool_input": {"file_path": "/tmp/test"}}"#;
        let input = parse_reader(json.as_bytes()).unwrap();
        assert_eq!(extract_command(&input), None);
    }

    #[test]
    fn parse_empty_input() {
        let json = r#"{}"#;
        let input = parse_reader(json.as_bytes()).unwrap();
        assert_eq!(extract_command(&input), None);
    }

    #[test]
    fn parse_invalid_json_returns_error() {
        let result = parse_reader("not json".as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn parse_reader_with_extra_fields() {
        let json = r#"{"tool_name": "Bash", "tool_input": {"command": "ls"}, "extra": true}"#;
        let input = parse_reader(json.as_bytes()).unwrap();
        assert_eq!(extract_command(&input), Some("ls"));
    }

    #[test]
    fn hook_input_is_clone() {
        let json = r#"{"tool_name": "Bash", "tool_input": {"command": "ls"}}"#;
        let input = parse_reader(json.as_bytes()).unwrap();
        let cloned = input.clone();
        assert_eq!(extract_command(&cloned), Some("ls"));
    }

    // ── Scannable content extraction ────────────────────────────

    #[test]
    fn extract_bash_scannable() {
        let json = r#"{"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}"#;
        let input = parse_reader(json.as_bytes()).unwrap();
        let items = extract_scannable_content(&input);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].context, ScanContext::BashCommand);
        assert_eq!(items[0].text, "rm -rf /");
    }

    #[test]
    fn extract_write_scannable() {
        let json = r#"{"tool_name": "Write", "tool_input": {"file_path": "/tmp/test.sh", "content": "rm -rf /"}}"#;
        let input = parse_reader(json.as_bytes()).unwrap();
        let items = extract_scannable_content(&input);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].context, ScanContext::WriteContent);
        assert!(items[0].context.downgrade_block());
    }

    #[test]
    fn extract_edit_scannable() {
        let json = r#"{"tool_name": "Edit", "tool_input": {"file_path": "/tmp/test.py", "old_string": "pass", "new_string": "DROP TABLE users"}}"#;
        let input = parse_reader(json.as_bytes()).unwrap();
        let items = extract_scannable_content(&input);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].context, ScanContext::EditNewString);
    }

    #[test]
    fn extract_notebook_scannable() {
        let json = r#"{"tool_name": "NotebookEdit", "tool_input": {"new_source": "import os; os.system('rm -rf /')"}}"#;
        let input = parse_reader(json.as_bytes()).unwrap();
        let items = extract_scannable_content(&input);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].context, ScanContext::NotebookCell);
    }

    #[test]
    fn extract_mcp_scannable() {
        let json = r#"{"tool_name": "mcp__kubernetes__k8s-pod-exec", "tool_input": {"command": "kubectl delete namespace prod", "namespace": "production"}}"#;
        let input = parse_reader(json.as_bytes()).unwrap();
        let items = extract_scannable_content(&input);
        assert!(items.len() >= 2); // command + namespace string
        assert!(items.iter().any(|i| i.context == ScanContext::McpCommand));
    }

    #[test]
    fn extract_read_tool_empty() {
        let json = r#"{"tool_name": "Read", "tool_input": {"file_path": "/etc/passwd"}}"#;
        let input = parse_reader(json.as_bytes()).unwrap();
        let items = extract_scannable_content(&input);
        assert!(items.is_empty());
    }

    #[test]
    fn extract_no_tool_input() {
        let json = r#"{"tool_name": "Bash"}"#;
        let input = parse_reader(json.as_bytes()).unwrap();
        let items = extract_scannable_content(&input);
        assert!(items.is_empty());
    }

    // ── Scan context ────────────────────────────────────────────

    #[test]
    fn bash_context_does_not_downgrade() {
        assert!(!ScanContext::BashCommand.downgrade_block());
    }

    #[test]
    fn write_context_downgrades() {
        assert!(ScanContext::WriteContent.downgrade_block());
    }

    #[test]
    fn mcp_context_does_not_downgrade() {
        assert!(!ScanContext::McpCommand.downgrade_block());
    }

    #[test]
    fn edit_context_downgrades() {
        assert!(ScanContext::EditNewString.downgrade_block());
    }

    #[test]
    fn notebook_context_downgrades() {
        assert!(ScanContext::NotebookCell.downgrade_block());
    }

    // ── Content line scanning ───────────────────────────────────

    #[test]
    fn scan_content_lines_filters_blanks_and_comments() {
        let content = "#!/bin/bash\n# comment\n\nrm -rf /\n// js comment\nls -la\n";
        let lines = scan_content_lines(content);
        // Only "rm -rf /" passes the prefilter — "ls -la" is safe and filtered out
        assert_eq!(lines, vec!["rm -rf /"]);
    }

    #[test]
    fn scan_content_lines_empty() {
        assert!(scan_content_lines("").is_empty());
        assert!(scan_content_lines("  \n  \n").is_empty());
    }

    // ── MCP bounds enforcement ───────────────────────────────

    #[test]
    fn mcp_max_strings_enforced() {
        // Build a JSON object with 100 string fields — should be capped at MCP_JSON_MAX_STRINGS
        let mut fields = String::new();
        for i in 0..100 {
            if i > 0 {
                fields.push_str(", ");
            }
            fields.push_str(&format!(r#""field_{i}": "value_{i}""#));
        }
        let json = format!(
            r#"{{"tool_name": "mcp__test__tool", "tool_input": {{{fields}}}}}"#
        );
        let input = parse_reader(json.as_bytes()).unwrap();
        let items = extract_scannable_content(&input);
        assert!(
            items.len() <= MCP_JSON_MAX_STRINGS,
            "expected at most {} items, got {}",
            MCP_JSON_MAX_STRINGS,
            items.len()
        );
    }

    #[test]
    fn mcp_max_depth_enforced() {
        // Build deeply nested JSON — should stop at MCP_JSON_MAX_DEPTH
        let mut json = r#"{"tool_name": "mcp__test__deep", "tool_input": {"a": "#.to_owned();
        for _ in 0..20 {
            json.push_str(r#"{"nested": "#);
        }
        json.push_str(r#""deep_value""#);
        for _ in 0..20 {
            json.push('}');
        }
        json.push_str("}}");
        let input = parse_reader(json.as_bytes()).unwrap();
        let items = extract_scannable_content(&input);
        // The deep value should NOT be collected due to depth limit
        assert!(
            !items.iter().any(|i| i.text == "deep_value"),
            "deep_value should not be collected at depth > {MCP_JSON_MAX_DEPTH}"
        );
    }

    #[test]
    fn mcp_with_command_field() {
        // MCP tool where `command` is a known field (not just in `extra`)
        let json = r#"{"tool_name": "mcp__k8s__exec", "tool_input": {"command": "kubectl get pods"}}"#;
        let input = parse_reader(json.as_bytes()).unwrap();
        let items = extract_scannable_content(&input);
        assert!(
            items.iter().any(|i| i.text == "kubectl get pods" && i.context == ScanContext::McpCommand),
            "command field should be extracted for MCP tools"
        );
    }

    #[test]
    fn scan_content_lines_prefilter_optimization() {
        // Safe lines are skipped by prefilter — no String allocation
        let content = "let x = 1;\nconst y = 2;\nfunction hello() {}";
        assert!(scan_content_lines(content).is_empty());

        // Dangerous lines pass through
        let content = "rm -rf /tmp\nDROP TABLE users";
        let lines = scan_content_lines(content);
        assert_eq!(lines.len(), 2);
    }
}
