use serde::Deserialize;

/// Claude Code PreToolUse hook payload.
#[derive(Debug, Clone, Deserialize)]
pub struct HookInput {
    pub tool_name: Option<String>,
    pub tool_input: Option<ToolInput>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ToolInput {
    pub command: Option<String>,
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

/// Extract the command string from a hook input.
#[must_use]
pub fn extract_command(input: &HookInput) -> Option<&str> {
    input.tool_input.as_ref()?.command.as_deref()
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
        let json = r#"{"tool_name": "Write", "tool_input": {}}"#;
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
}
