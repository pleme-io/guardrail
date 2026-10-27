//! The commands a shell line runs, each read from its command position.
//!
//! A rule that names a command (`reboot`, `systemctl reboot`) must not fire on
//! the same word inside another program's argument: `rg -i "reboot|halt"` runs
//! `rg`. The lexer here honours quotes, so an operator inside a quoted pattern
//! does not open a segment, then resolves each segment's head past assignments,
//! keywords and wrappers (`sudo`, `env`, `nohup`, …). A command handed on as a
//! string is a command too: `ssh host '<cmd>'`, `sh -c '<cmd>'`, `eval`, `$(…)`,
//! backticks and a heredoc fed to a shell are lexed again, to a fixed depth.

use std::path::Path;

/// Nesting depth past which a handed-on command string is not lexed again.
const MAX_DEPTH: usize = 8;

/// Shell words that precede a command without being one.
const KEYWORDS: &[&str] = &[
    "!", "{", "}", "if", "then", "else", "elif", "fi", "do", "done", "while", "until", "time",
];

/// Shells that run a `-c` string or a heredoc body as commands.
const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "fish"];

/// ssh flags that take a value, so the host is the first word after them.
const SSH_VALUE_FLAGS: &[&str] = &[
    "-B", "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p",
    "-Q", "-R", "-S", "-W", "-w",
];

/// A wrapper whose argument is the real command: its name, the flags that take
/// a value, and how many positional words it reads before the command.
struct Wrapper {
    name: &'static str,
    value_flags: &'static [&'static str],
    positionals: usize,
}

const WRAPPERS: &[Wrapper] = &[
    Wrapper {
        name: "sudo",
        value_flags: &["-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U", "-T"],
        positionals: 0,
    },
    Wrapper {
        name: "doas",
        value_flags: &["-u", "-C"],
        positionals: 0,
    },
    Wrapper {
        name: "env",
        value_flags: &["-u", "-C", "-S"],
        positionals: 0,
    },
    Wrapper {
        name: "nohup",
        value_flags: &[],
        positionals: 0,
    },
    Wrapper {
        name: "exec",
        value_flags: &["-a"],
        positionals: 0,
    },
    Wrapper {
        name: "command",
        value_flags: &[],
        positionals: 0,
    },
    Wrapper {
        name: "builtin",
        value_flags: &[],
        positionals: 0,
    },
    Wrapper {
        name: "nice",
        value_flags: &["-n"],
        positionals: 0,
    },
    Wrapper {
        name: "setsid",
        value_flags: &[],
        positionals: 0,
    },
    Wrapper {
        name: "stdbuf",
        value_flags: &["-i", "-o", "-e"],
        positionals: 0,
    },
    Wrapper {
        name: "timeout",
        value_flags: &["-s", "-k"],
        positionals: 1,
    },
    Wrapper {
        name: "xargs",
        value_flags: &["-n", "-I", "-L", "-P", "-d", "-E", "-s", "-a"],
        positionals: 0,
    },
];

#[derive(Default)]
struct Segment {
    words: Vec<String>,
    heredocs: Vec<String>,
}

#[derive(Default)]
struct Lexed {
    segments: Vec<Segment>,
    nested: Vec<String>,
}

/// Every command `text` runs, each as its head's basename followed by its
/// unquoted arguments, one space apart.
#[must_use]
pub fn commands(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    collect(text, 0, &mut out);
    out
}

/// Index of the word a segment executes: past `VAR=value` assignments, shell
/// keywords, and wrappers with their flags and positional words.
#[must_use]
pub fn command_head<S: AsRef<str>>(words: &[S]) -> Option<usize> {
    let mut i = 0;
    while i < words.len() {
        let w = words[i].as_ref();
        if is_assignment(w) || KEYWORDS.contains(&w) || w.starts_with('-') {
            i += 1;
            continue;
        }
        let Some(wrapper) = WRAPPERS.iter().find(|x| x.name == basename(w)) else {
            return Some(i);
        };
        i += 1;
        while i < words.len() {
            let flag = words[i].as_ref();
            if is_assignment(flag) {
                i += 1;
            } else if flag.starts_with('-') {
                i += if wrapper.value_flags.contains(&flag) {
                    2
                } else {
                    1
                };
            } else {
                break;
            }
        }
        i += wrapper.positionals;
    }
    None
}

fn collect(text: &str, depth: usize, out: &mut Vec<String>) {
    if depth > MAX_DEPTH {
        return;
    }
    let lexed = lex(text);
    for inner in &lexed.nested {
        collect(inner, depth + 1, out);
    }
    for segment in &lexed.segments {
        resolve(segment, depth, out);
    }
}

fn resolve(segment: &Segment, depth: usize, out: &mut Vec<String>) {
    let words = &segment.words;
    let Some(head) = command_head(words) else {
        return;
    };
    let name = basename(&words[head]);
    let rest = &words[head + 1..];
    let handed_on = match name {
        "ssh" => ssh_remote(rest),
        "eval" => Some(rest.join(" ")),
        n if SHELLS.contains(&n) => shell_script(rest),
        _ => None,
    };
    if let Some(inner) = handed_on {
        collect(&inner, depth + 1, out);
    }
    if name == "ssh" || SHELLS.contains(&name) {
        for body in &segment.heredocs {
            collect(body, depth + 1, out);
        }
    }
    let mut command = name.to_owned();
    for w in rest {
        command.push(' ');
        command.push_str(w);
    }
    out.push(command);
}

/// The remote command of `ssh [flags] host <cmd…>`, joined as ssh joins it.
fn ssh_remote(args: &[String]) -> Option<String> {
    let mut i = 0;
    while i < args.len() && args[i].starts_with('-') {
        i += if SSH_VALUE_FLAGS.contains(&args[i].as_str()) {
            2
        } else {
            1
        };
    }
    let remote = args.get(i + 1..)?;
    (!remote.is_empty()).then(|| remote.join(" "))
}

/// The script of `sh -c '<cmd>'` (also `-lc`, `-ec`, …).
fn shell_script(args: &[String]) -> Option<String> {
    let at = args
        .iter()
        .position(|a| a.starts_with('-') && !a.starts_with("--") && a.contains('c'))?;
    args[at + 1..].iter().find(|a| !a.starts_with('-')).cloned()
}

fn basename(word: &str) -> &str {
    Path::new(word)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(word)
}

fn is_assignment(w: &str) -> bool {
    w.split_once('=').is_some_and(|(k, _)| {
        !k.is_empty()
            && !k.as_bytes()[0].is_ascii_digit()
            && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    })
}

struct Lexer<'a> {
    chars: Vec<char>,
    pos: usize,
    word: String,
    in_word: bool,
    segment: Segment,
    pending: Vec<(String, bool)>,
    out: &'a mut Lexed,
}

fn lex(text: &str) -> Lexed {
    let mut out = Lexed::default();
    let mut lx = Lexer {
        chars: text.chars().collect(),
        pos: 0,
        word: String::new(),
        in_word: false,
        segment: Segment::default(),
        pending: Vec::new(),
        out: &mut out,
    };
    lx.run();
    out
}

impl Lexer<'_> {
    fn peek(&self, ahead: usize) -> Option<char> {
        self.chars.get(self.pos + ahead).copied()
    }

    fn push_char(&mut self, c: char) {
        self.word.push(c);
        self.in_word = true;
    }

    fn end_word(&mut self) {
        if self.in_word {
            self.segment.words.push(std::mem::take(&mut self.word));
            self.in_word = false;
        }
    }

    fn end_segment(&mut self) {
        self.end_word();
        let segment = std::mem::take(&mut self.segment);
        if !segment.words.is_empty() || !segment.heredocs.is_empty() {
            self.out.segments.push(segment);
        }
    }

    fn run(&mut self) {
        while let Some(c) = self.peek(0) {
            self.pos += 1;
            match c {
                ' ' | '\t' => self.end_word(),
                '\n' => {
                    self.end_word();
                    self.read_heredocs();
                    self.end_segment();
                }
                '&' if self.word.ends_with(['>', '<']) || self.peek(0) == Some('>') => {
                    self.push_char(c);
                }
                ';' | '&' | '|' | '(' | ')' => self.end_segment(),
                '\\' => match self.peek(0) {
                    Some('\n') => self.pos += 1,
                    Some(n) => {
                        self.pos += 1;
                        self.push_char(n);
                    }
                    None => {}
                },
                '\'' => {
                    self.in_word = true;
                    while let Some(n) = self.peek(0) {
                        self.pos += 1;
                        if n == '\'' {
                            break;
                        }
                        self.word.push(n);
                    }
                }
                '"' => self.double_quoted(),
                '`' => self.backtick(),
                '$' if self.peek(0) == Some('(') => {
                    self.pos += 1;
                    self.substitution();
                    self.in_word = true;
                }
                '#' if !self.in_word => {
                    while self.peek(0).is_some_and(|n| n != '\n') {
                        self.pos += 1;
                    }
                }
                '<' if self.peek(0) == Some('<') && self.peek(1) != Some('<') => {
                    self.pos += 1;
                    self.heredoc_marker();
                }
                _ => self.push_char(c),
            }
        }
        self.end_segment();
    }

    fn double_quoted(&mut self) {
        self.in_word = true;
        while let Some(n) = self.peek(0) {
            self.pos += 1;
            match n {
                '"' => return,
                '\\' => {
                    if let Some(e) = self.peek(0) {
                        self.pos += 1;
                        if !matches!(e, '"' | '\\' | '$' | '`' | '\n') {
                            self.word.push('\\');
                        }
                        if e != '\n' {
                            self.word.push(e);
                        }
                    }
                }
                '`' => self.backtick(),
                '$' if self.peek(0) == Some('(') => {
                    self.pos += 1;
                    self.substitution();
                }
                _ => self.word.push(n),
            }
        }
    }

    fn backtick(&mut self) {
        let mut inner = String::new();
        while let Some(n) = self.peek(0) {
            self.pos += 1;
            match n {
                '`' => break,
                '\\' => {
                    if let Some(e) = self.peek(0) {
                        self.pos += 1;
                        inner.push(e);
                    }
                }
                _ => inner.push(n),
            }
        }
        self.in_word = true;
        self.out.nested.push(inner);
    }

    fn substitution(&mut self) {
        let mut inner = String::new();
        let mut depth = 1usize;
        let mut quote: Option<char> = None;
        while let Some(n) = self.peek(0) {
            self.pos += 1;
            match (quote, n) {
                (Some(q), _) if n == q => quote = None,
                (Some(_), _) => {}
                (None, '\'' | '"') => quote = Some(n),
                (None, '(') => depth += 1,
                (None, ')') => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            inner.push(n);
        }
        self.out.nested.push(inner);
    }

    fn heredoc_marker(&mut self) {
        self.end_word();
        let strip_tabs = self.peek(0) == Some('-');
        if strip_tabs {
            self.pos += 1;
        }
        while self.peek(0).is_some_and(|c| c == ' ' || c == '\t') {
            self.pos += 1;
        }
        let mut delimiter = String::new();
        while let Some(c) = self.peek(0) {
            if c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | ')' | '<' | '>') {
                break;
            }
            self.pos += 1;
            if !matches!(c, '\'' | '"' | '\\') {
                delimiter.push(c);
            }
        }
        if !delimiter.is_empty() {
            self.pending.push((delimiter, strip_tabs));
        }
    }

    fn read_heredocs(&mut self) {
        for (delimiter, strip_tabs) in std::mem::take(&mut self.pending) {
            let mut body = String::new();
            while self.pos < self.chars.len() {
                let start = self.pos;
                while self.peek(0).is_some_and(|c| c != '\n') {
                    self.pos += 1;
                }
                let line: String = self.chars[start..self.pos].iter().collect();
                if self.peek(0) == Some('\n') {
                    self.pos += 1;
                }
                let bare = if strip_tabs {
                    line.trim_start_matches('\t')
                } else {
                    &line
                };
                if bare == delimiter {
                    break;
                }
                body.push_str(bare);
                body.push('\n');
            }
            self.segment.heredocs.push(body);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn heads(text: &str) -> Vec<String> {
        commands(text)
            .into_iter()
            .map(|c| c.split(' ').next().unwrap_or("").to_owned())
            .collect()
    }

    #[test]
    fn an_operator_inside_quotes_opens_no_segment() {
        assert_eq!(heads(r#"rg -i "eboot|poweroff|halt" log"#), ["rg"]);
        assert_eq!(heads("grep -E 'a;reboot&&halt' x"), ["grep"]);
    }

    #[test]
    fn operators_outside_quotes_split() {
        assert_eq!(heads("true && poweroff"), ["true", "poweroff"]);
        assert_eq!(heads("a; b | c || d & e"), ["a", "b", "c", "d", "e"]);
        assert_eq!(heads("( halt )"), ["halt"]);
    }

    #[test]
    fn wrappers_and_assignments_are_skipped() {
        assert_eq!(heads("sudo -u root reboot"), ["reboot"]);
        assert_eq!(heads("env A=1 nohup nice -n 5 /sbin/reboot"), ["reboot"]);
        assert_eq!(heads("FOO=1 timeout -s KILL 5 halt"), ["halt"]);
        assert_eq!(heads("if true; then reboot; fi"), ["true", "reboot"]);
    }

    #[test]
    fn a_handed_on_command_string_is_lexed_again() {
        assert!(commands("ssh -p 22 rio 'sudo reboot'").contains(&"reboot".to_owned()));
        assert!(
            commands("ssh rio sudo systemctl poweroff").contains(&"systemctl poweroff".to_owned())
        );
        assert!(commands("bash -lc 'echo hi; halt'").contains(&"halt".to_owned()));
        assert!(commands("eval 'reboot'").contains(&"reboot".to_owned()));
        assert!(commands("echo \"$(reboot)\"").contains(&"reboot".to_owned()));
        assert!(commands("echo `halt`").contains(&"halt".to_owned()));
        assert!(commands("ssh rio <<'EOF'\nsudo reboot\nEOF").contains(&"reboot".to_owned()));
    }

    #[test]
    fn a_quoted_pattern_in_a_remote_command_stays_an_argument() {
        let cmds = commands(
            r#"ssh rio 'journalctl -b -2 --no-pager | rg -i "eboot|power-off|poweroff|halt"'"#,
        );
        assert_eq!(
            cmds,
            [
                "journalctl -b -2 --no-pager",
                "rg -i eboot|power-off|poweroff|halt",
                "ssh rio journalctl -b -2 --no-pager | rg -i \"eboot|power-off|poweroff|halt\"",
            ]
        );
    }

    #[test]
    fn a_heredoc_body_is_data_unless_a_shell_reads_it() {
        assert_eq!(heads("cat <<EOF\nreboot\nEOF\necho done"), ["cat", "echo"]);
        assert_eq!(
            heads("git commit -m \"$(cat <<'EOF'\nhalt floor\nEOF\n)\""),
            ["cat", "git"]
        );
    }

    #[test]
    fn redirections_do_not_split() {
        assert_eq!(heads("reboot 2>&1 >/dev/null"), ["reboot"]);
        assert_eq!(heads("make &> log"), ["make"]);
    }

    #[test]
    fn a_comment_runs_nothing() {
        assert_eq!(heads("ls # then reboot"), ["ls"]);
    }
}
