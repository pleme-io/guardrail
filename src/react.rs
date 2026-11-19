use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const DEFAULT_SOUND: &str = "/System/Library/Sounds/Glass.aiff";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Reaction {
    Mark,
    Sound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Spec {
    pub reaction: Reaction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sound: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_turn_secs: Option<u64>,
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    Write { file: PathBuf, secs: u64 },
    Spawn(Vec<String>),
}

#[must_use]
pub fn session_key(payload: &Value) -> Option<String> {
    let id = payload.get("session_id")?.as_str()?;
    let key: String = id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    (!key.is_empty() && key.len() == id.len()).then_some(key)
}

#[must_use]
pub fn plan(spec: &Spec, session: &str, dir: &Path, now: u64, started: Option<u64>) -> Vec<Effect> {
    if !spec.enabled {
        return Vec::new();
    }
    let file = dir.join(session);
    match spec.reaction {
        Reaction::Mark => vec![Effect::Write { file, secs: now }],
        Reaction::Sound => {
            let long_enough = match spec.min_turn_secs {
                None => true,
                Some(min) => started.is_some_and(|s| now.saturating_sub(s) >= min),
            };
            if !long_enough {
                return Vec::new();
            }
            let sound = spec.sound.clone().unwrap_or_else(|| DEFAULT_SOUND.into());
            vec![Effect::Spawn(vec!["/usr/bin/afplay".into(), sound])]
        }
    }
}

fn read_start(dir: &Path, session: &str) -> Option<u64> {
    fs::read_to_string(dir.join(session))
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn apply(effect: &Effect) -> std::io::Result<()> {
    match effect {
        Effect::Write { file, secs } => {
            if let Some(parent) = file.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(file, secs.to_string())
        }
        Effect::Spawn(argv) => {
            let Some((program, args)) = argv.split_first() else {
                return Ok(());
            };
            Command::new(program)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map(drop)
        }
    }
}

#[must_use]
pub fn state_dir() -> Option<PathBuf> {
    let base = okiba::Okiba::for_app("guardrail")
        .base(okiba::Tier::State)
        .ok()?;
    Some(base.join("guardrail").join("turns").as_path().to_path_buf())
}

pub fn run_in(spec: &Spec, raw: &str, dir: &Path, now: u64) {
    let payload: Value = serde_json::from_str(raw).unwrap_or(Value::Null);
    let Some(session) = session_key(&payload) else {
        return;
    };
    let started = read_start(dir, &session);
    for effect in plan(spec, &session, dir, now, started) {
        if let Err(e) = apply(&effect) {
            eprintln!("guardrail hook: react: {e}");
        }
    }
}

pub fn run(spec: &Spec, raw: &str) {
    let Some(dir) = state_dir() else {
        return;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    run_in(spec, raw, &dir, now);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(reaction: Reaction, min: Option<u64>, enabled: bool) -> Spec {
        Spec {
            reaction,
            sound: None,
            min_turn_secs: min,
            enabled,
        }
    }

    const DIR: &str = "/state";

    fn p(s: &Spec, now: u64, started: Option<u64>) -> Vec<Effect> {
        plan(s, "abc", Path::new(DIR), now, started)
    }

    #[test]
    fn a_disabled_reaction_does_nothing_in_every_shape() {
        for r in [Reaction::Mark, Reaction::Sound] {
            assert!(p(&spec(r, None, false), 100, Some(0)).is_empty());
        }
    }

    #[test]
    fn mark_records_the_turn_start_under_the_session() {
        assert_eq!(
            p(&spec(Reaction::Mark, None, true), 77, None),
            vec![Effect::Write {
                file: PathBuf::from("/state/abc"),
                secs: 77
            }]
        );
    }

    #[test]
    fn sound_fires_only_for_a_turn_at_least_min_long() {
        let s = spec(Reaction::Sound, Some(60), true);
        assert!(p(&s, 159, Some(100)).is_empty());
        assert_eq!(p(&s, 160, Some(100)).len(), 1);
        assert_eq!(p(&s, 500, Some(100)).len(), 1);
    }

    #[test]
    fn a_threshold_with_no_recorded_start_stays_silent() {
        assert!(p(&spec(Reaction::Sound, Some(60), true), 1000, None).is_empty());
    }

    #[test]
    fn a_clock_behind_the_mark_does_not_fire() {
        assert!(p(&spec(Reaction::Sound, Some(1), true), 5, Some(100)).is_empty());
    }

    #[test]
    fn sound_with_no_threshold_always_fires_and_defaults_the_file() {
        assert_eq!(
            p(&spec(Reaction::Sound, None, true), 0, None),
            vec![Effect::Spawn(vec![
                "/usr/bin/afplay".into(),
                DEFAULT_SOUND.into()
            ])]
        );
    }

    #[test]
    fn a_named_sound_replaces_the_default() {
        let mut s = spec(Reaction::Sound, None, true);
        s.sound = Some("/x/y.aiff".into());
        assert_eq!(
            p(&s, 0, None),
            vec![Effect::Spawn(vec![
                "/usr/bin/afplay".into(),
                "/x/y.aiff".into()
            ])]
        );
    }

    #[test]
    fn a_session_id_that_could_escape_the_state_dir_is_refused() {
        for bad in ["../x", "a/b", "", "a b", "a\u{0}b"] {
            assert_eq!(session_key(&serde_json::json!({ "session_id": bad })), None);
        }
        assert_eq!(
            session_key(&serde_json::json!({ "session_id": "ab-12_C" })),
            Some("ab-12_C".into())
        );
        assert_eq!(session_key(&Value::Null), None);
    }

    #[test]
    fn a_long_turn_end_to_end_marks_then_reacts_and_a_short_one_does_not() {
        let tmp = tempfile::tempdir().unwrap();
        let raw = r#"{"session_id":"s1"}"#;
        run_in(&spec(Reaction::Mark, None, true), raw, tmp.path(), 1000);
        assert_eq!(read_start(tmp.path(), "s1"), Some(1000));
        let s = spec(Reaction::Sound, Some(60), true);
        let started = read_start(tmp.path(), "s1");
        assert!(plan(&s, "s1", tmp.path(), 1030, started).is_empty());
        assert_eq!(plan(&s, "s1", tmp.path(), 1060, started).len(), 1);
    }

    #[test]
    fn an_unwritable_state_dir_fails_open() {
        let tmp = tempfile::tempdir().unwrap();
        let blocker = tmp.path().join("file");
        fs::write(&blocker, "x").unwrap();
        run_in(
            &spec(Reaction::Mark, None, true),
            r#"{"session_id":"s1"}"#,
            &blocker.join("sub"),
            5,
        );
    }

    #[test]
    fn a_payload_with_no_session_does_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        run_in(&spec(Reaction::Mark, None, true), "{}", tmp.path(), 5);
        assert_eq!(fs::read_dir(tmp.path()).unwrap().count(), 0);
    }
}
