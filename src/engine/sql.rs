use std::borrow::Cow;
use std::sync::LazyLock;

use hayai::engine::Normalizer;

static SQL_BLOCK_COMMENT_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"/\*.*?\*/").expect("SQL block comment regex is valid"));

static SQL_LINE_COMMENT_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?m)(?:^|[ \t])-- [^-].*$")
        .expect("SQL line comment regex is valid")
});

/// Strips SQL block comments (`/* ... */`) and line comments (`-- ...`).
/// Preserves `--` when it appears as a CLI flag (preceded by a word char).
#[derive(Debug, Clone, Copy, Default)]
pub struct SqlCommentStripper;

impl Normalizer for SqlCommentStripper {
    fn normalize<'a>(&self, command: &'a str) -> Cow<'a, str> {
        let has_block = SQL_BLOCK_COMMENT_RE.is_match(command);
        let has_line = SQL_LINE_COMMENT_RE.is_match(command);
        if !has_block && !has_line {
            return Cow::Borrowed(command);
        }
        let mut result = if has_block {
            SQL_BLOCK_COMMENT_RE.replace_all(command, " ").into_owned()
        } else {
            command.to_owned()
        };
        if has_line || SQL_LINE_COMMENT_RE.is_match(&result) {
            result = SQL_LINE_COMMENT_RE.replace_all(&result, "").into_owned();
        }
        Cow::Owned(result)
    }
}
