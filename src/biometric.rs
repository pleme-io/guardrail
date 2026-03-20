//! Biometric authentication for guardrail bypass on macOS.
//!
//! When a rule blocks a command, the user can authenticate via Touch ID
//! to override the block. This provides a hardware-backed "are you sure?"
//! gate without completely disabling safety rules.
//!
//! On non-macOS platforms, [`authenticate`] always returns `false`.

use std::io::IsTerminal;

/// Prompt the user for biometric authentication to bypass a guardrail block.
///
/// Returns `true` if the user successfully authenticated, `false` otherwise.
/// Always returns `false` on non-macOS platforms or when stdin is not a TTY
/// (e.g. when running in a non-interactive pipe).
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

    // Minimal Swift script using LocalAuthentication framework.
    // LAPolicy.deviceOwnerAuthentication uses Touch ID with password fallback.
    // Exit code 0 = authenticated, 1 = denied/cancelled.
    let swift_code = format!(
        r#"
import LocalAuthentication
import Foundation

let context = LAContext()
var error: NSError?

guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {{
    exit(1)
}}

let semaphore = DispatchSemaphore(value: 0)
var success = false

context.evaluatePolicy(
    .deviceOwnerAuthentication,
    localizedReason: "guardrail [{rule}]: {message}"
) {{ result, _ in
    success = result
    semaphore.signal()
}}

semaphore.wait()
exit(success ? 0 : 1)
"#
    );

    let result = std::process::Command::new("/usr/bin/swift")
        .args(["-e", &swift_code])
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
}
