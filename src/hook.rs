use serde::Deserialize;

/// Claude Code PreToolUse hook payload.
#[derive(Debug, Deserialize)]
pub struct HookInput {
    pub tool_name: Option<String>,
    pub tool_input: Option<ToolInput>,
}

#[derive(Debug, Deserialize)]
pub struct ToolInput {
    pub command: Option<String>,
}

/// Parse hook JSON from stdin.
///
/// # Errors
///
/// Returns an error if stdin can't be read or parsed.
pub fn parse_stdin() -> anyhow::Result<HookInput> {
    let input = std::io::read_to_string(std::io::stdin())?;
    Ok(serde_json::from_str(&input)?)
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
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(extract_command(&input), Some("ls -la"));
    }

    #[test]
    fn parse_missing_command() {
        let json = r#"{"tool_name": "Write", "tool_input": {}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(extract_command(&input), None);
    }

    #[test]
    fn parse_empty_input() {
        let json = r#"{}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(extract_command(&input), None);
    }
}
