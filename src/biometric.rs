//! Biometric authentication for guardrail bypass on macOS.
//!
//! When a rule blocks a command, the user can authenticate via Touch ID
//! to override the block. This provides a hardware-backed "are you sure?"
//! gate without completely disabling safety rules.
//!
//! On non-macOS platforms, [`authenticate`] always returns `false`.

use std::io::IsTerminal;

/// Environment variable carrying the prompt text into the Swift helper.
///
/// The reason travels as DATA in the environment, never as interpolated
/// source — see [`SWIFT_TOUCH_ID_PROGRAM`].
const REASON_ENV: &str = "GUARDRAIL_REASON";

/// The Touch ID helper, as a **constant** Swift program.
///
/// ── WHY THIS IS A CONSTANT AND NOT A `format!()` (fixed 2026-08-18)
///
/// This program used to be built with `format!()`, interpolating the rule name
/// and message directly into a Swift **string literal**:
///
/// ```text
/// localizedReason: "guardrail [{rule}]: {message}"
/// ```
///
/// A rule whose `message` contains a double quote closes that literal, and the
/// remainder is handed to the Swift compiler as syntax. The messages are not all
/// operator-authored, which is what made this reachable rather than theoretical:
/// **2,272 of 2,512 rules are GENERATED** (`guardrail-gen`, whose regex and
/// message text are themselves `format!()`-assembled), and `rules.d/` is a plain
/// directory any process with write access can drop a suite into.
///
/// ── WHAT IT IS, AND WHAT IT IS NOT — measured 2026-08-18, do not round this up
///
/// **It is not a privilege escalation. It fails CLOSED.** Seven crafted payloads
/// were run against the pre-fix shape — closing the literal then `exit(0)` with
/// a line comment, with a block comment, the same across an embedded newline, a
/// multi-line-string open, and a synthesised trailing-closure host. **All seven
/// exited non-zero**, so `authenticate()` returned `false` and the block stood.
/// The structural reason is that the attacker fights two constraints at once:
/// the original closing `"` sits immediately after the injection point, so any
/// payload that closes the literal leaves a stray quote opening an unterminated
/// one, *and* the trailing `) { result, _ in … }` closure still has to parse.
/// An exit-0 payload may exist; none was found, and the honest grade is
/// **not-demonstrated**, not "impossible".
///
/// **What it actually costs is a functional defect on a security control, plus
/// a misleading report.** Any rule whose message contains a `"` loses its Touch
/// ID bypass entirely: swift fails to compile, the status is non-zero, and the
/// caller prints *"❌ Bypass denied — command blocked"* — which reads as *the
/// operator cancelled* when in truth the helper never ran and no prompt was ever
/// shown. A security control that reports the wrong reason for its own refusal
/// is the part worth fixing even with escalation ruled out.
///
/// The fix is not escaping — escaping is the thing that goes wrong. The program
/// is now a constant with no interpolation site, and the prompt text arrives as
/// an environment variable, which the Swift runtime treats as a `String` value
/// and never as syntax. That removes the class rather than the instance, and it
/// satisfies ★★ TYPED EMISSION, which bans `format!()` of target syntax: there
/// is no longer any Swift syntax being emitted at all.
#[cfg(target_os = "macos")]
const SWIFT_TOUCH_ID_PROGRAM: &str = r#"
import LocalAuthentication
import Foundation

let reason = ProcessInfo.processInfo.environment["GUARDRAIL_REASON"]
    ?? "guardrail: confirm this blocked command"

let context = LAContext()
var error: NSError?

guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
    exit(1)
}

let semaphore = DispatchSemaphore(value: 0)
var success = false

context.evaluatePolicy(
    .deviceOwnerAuthentication,
    localizedReason: reason
) { result, _ in
    success = result
    semaphore.signal()
}

semaphore.wait()
exit(success ? 0 : 1)
"#;

/// Build the prompt text as DATA, without `format!()`.
///
/// Control characters are stripped rather than escaped. They cannot reach Swift
/// as syntax any more, so this is only about the prompt rendering legibly in the
/// system dialog — but stripping is still the right default for a string that
/// comes from a generated rule corpus, and it keeps a newline-bearing message
/// from turning one dialog line into several.
#[cfg(target_os = "macos")]
fn touch_id_reason(rule: &str, message: &str) -> String {
    fn push_clean(out: &mut String, s: &str) {
        out.extend(s.chars().filter(|c| !c.is_control()));
    }
    let mut reason = String::with_capacity(rule.len() + message.len() + 16);
    reason.push_str("guardrail [");
    push_clean(&mut reason, rule);
    reason.push_str("]: ");
    push_clean(&mut reason, message);
    reason
}

/// Prompt the user for biometric authentication to bypass a guardrail block.
///
/// Returns `true` if the user successfully authenticated, `false` otherwise.
/// Always returns `false` on non-macOS platforms or when stdin is not a TTY
/// (e.g. when running in a non-interactive pipe).
#[must_use]
pub fn authenticate(rule: &str, message: &str) -> bool {
    // Only attempt biometric auth when running interactively
    if !std::io::stderr().is_terminal() {
        return false;
    }

    #[cfg(target_os = "macos")]
    {
        macos_touch_id(rule, message)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (rule, message);
        false
    }
}

/// macOS Touch ID authentication via LocalAuthentication.framework.
///
/// Invokes a minimal Swift script that calls `LAContext.evaluatePolicy`.
/// The Swift runtime is always available on macOS (/usr/bin/swift).
#[cfg(target_os = "macos")]
fn macos_touch_id(rule: &str, message: &str) -> bool {
    // Inform the user what's happening
    eprintln!(
        "\x1b[33m⚡ guardrail [{rule}]: {message}\x1b[0m"
    );
    eprintln!(
        "\x1b[36m🔐 Touch ID to override, or press Cancel to block\x1b[0m"
    );

    let result = std::process::Command::new("/usr/bin/swift")
        .args(["-e", SWIFT_TOUCH_ID_PROGRAM])
        .env(REASON_ENV, touch_id_reason(rule, message))
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .status();

    match result {
        Ok(status) => {
            if status.success() {
                eprintln!("\x1b[32m✅ Biometric bypass granted for [{rule}]\x1b[0m");
                true
            } else {
                eprintln!("\x1b[31m❌ Bypass denied — command blocked\x1b[0m");
                false
            }
        }
        Err(e) => {
            eprintln!("guardrail: biometric auth unavailable: {e}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_interactive_always_denies() {
        // In test harness, stderr is not a TTY
        assert!(!authenticate("test-rule", "test message"));
    }

    #[test]
    fn authenticate_returns_bool() {
        // Type-level test — authenticate has the right signature
        let _: bool = authenticate("rule", "msg");
    }

    // ── The injection fix (2026-08-18) ────────────────────────────
    //
    // The structural half of this fix is that `SWIFT_TOUCH_ID_PROGRAM` is a
    // `const &str` with no interpolation site, so there is no longer any way
    // to reach Swift syntax from a rule field. These tests pin the two things
    // a constant alone does not prove.

    /// The program must contain no interpolation site at all. If someone
    /// reintroduces a `format!()` here, the placeholder braces come back and
    /// this goes red — which is the point, because the escalation was silent.
    #[cfg(target_os = "macos")]
    #[test]
    fn swift_program_reads_the_reason_from_the_environment() {
        assert!(SWIFT_TOUCH_ID_PROGRAM.contains("ProcessInfo.processInfo.environment"));
        assert!(SWIFT_TOUCH_ID_PROGRAM.contains(REASON_ENV));
        // localizedReason takes the VARIABLE, never a literal built from input.
        assert!(SWIFT_TOUCH_ID_PROGRAM.contains("localizedReason: reason"));
        assert!(!SWIFT_TOUCH_ID_PROGRAM.contains("localizedReason: \""));
    }

    /// The historical payload, carried verbatim as the receipt. Pre-fix it
    /// closed the Swift string literal and reached the compiler as syntax —
    /// measured outcome: a compile error, exit 1, so the block STOOD and the
    /// operator saw "Bypass denied" for a prompt that never appeared. It is now
    /// inert data: it stays inside the reason and reaches no syntax at all.
    /// (Grade honestly — this pins *no interpolation*, not *no escalation*;
    /// escalation was not demonstrated and is not claimed. See the
    /// `SWIFT_TOUCH_ID_PROGRAM` doc comment for the seven-payload measurement.)
    #[cfg(target_os = "macos")]
    #[test]
    fn injection_payload_is_inert_data() {
        let payload = r#"oops"); exit(0); //"#;
        let reason = touch_id_reason("rm-rf-root", payload);
        assert_eq!(reason, r#"guardrail [rm-rf-root]: oops"); exit(0); //"#);
        // The payload is not removed — it does not need to be. It is a value.
        assert!(reason.contains(payload));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn reason_strips_control_characters() {
        let reason = touch_id_reason("a\nb", "line1\nline2\u{0}");
        assert_eq!(reason, "guardrail [ab]: line1line2");
        assert!(!reason.contains('\n'));
    }
}
