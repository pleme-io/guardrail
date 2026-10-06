//! The config schema as the serde derives define it, for the Nix module's parity check.
//!
//! Field names are read from what each `Deserialize` impl asks for, so the
//! table cannot disagree with the structs: a field added to a struct appears
//! here without anyone listing it.

use serde::de::{self, Deserialize, Deserializer, Visitor};
use std::collections::BTreeSet;

use serde_json::{Value, json};

use crate::dispatch::Builtin;
use crate::model::{
    ChangeWindow, ExampleCall, GuardrailConfig, PrefilterOverrides, Rule, RuleExamples,
    ToolInputLimit,
};

#[derive(Default)]
struct Probe {
    names: Option<&'static [&'static str]>,
}

impl<'de> Deserializer<'de> for &mut Probe {
    type Error = de::value::Error;

    fn deserialize_any<V: Visitor<'de>>(self, _: V) -> Result<V::Value, Self::Error> {
        Err(de::Error::custom("probe"))
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        fields: &'static [&'static str],
        _: V,
    ) -> Result<V::Value, Self::Error> {
        self.names = Some(fields);
        Err(de::Error::custom("probe"))
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _: &'static str,
        variants: &'static [&'static str],
        _: V,
    ) -> Result<V::Value, Self::Error> {
        self.names = Some(variants);
        Err(de::Error::custom("probe"))
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map identifier ignored_any
    }
}

/// The field names a struct's `Deserialize` accepts, or the variant names of an enum.
#[must_use]
pub fn names_of<'de, T: Deserialize<'de>>() -> Vec<&'static str> {
    let mut probe = Probe::default();
    let _ = T::deserialize(&mut probe);
    probe.names.unwrap_or_default().to_vec()
}

/// Every config key the binary accepts, by struct.
#[must_use]
pub fn schema() -> Value {
    let mut actions = names_of::<Builtin>();
    actions.push("exec");
    json!({
        "config": names_of::<GuardrailConfig>(),
        "rule": names_of::<Rule>(),
        "examples": names_of::<RuleExamples>(),
        "exampleCall": names_of::<ExampleCall>(),
        "toolInputLimit": names_of::<ToolInputLimit>(),
        "changeWindow": names_of::<ChangeWindow>(),
        "prefilter": names_of::<PrefilterOverrides>(),
        "actions": actions,
    })
}

/// Every key one side has and the other lacks, by struct; empty when they agree.
#[must_use]
pub fn drift(expected: &Value) -> Vec<String> {
    let names = |v: &Value| -> BTreeSet<String> {
        v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };
    let ours = schema();
    let mut out = Vec::new();
    let mut structs: BTreeSet<&String> = BTreeSet::new();
    if let (Some(a), Some(b)) = (ours.as_object(), expected.as_object()) {
        structs.extend(a.keys());
        structs.extend(b.keys());
    }
    for s in structs {
        let (here, there) = (names(&ours[s]), names(&expected[s]));
        for k in here.difference(&there) {
            out.push(format!(
                "{s}.{k}: accepted by guardrail, missing from the other side"
            ));
        }
        for k in there.difference(&here) {
            out.push(format!(
                "{s}.{k}: on the other side, not accepted by guardrail"
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rule_table_is_what_the_struct_accepts() {
        assert_eq!(
            names_of::<Rule>(),
            [
                "name",
                "pattern",
                "severity",
                "message",
                "category",
                "test_block",
                "test_allow",
                "window",
                "examples",
                "tools",
                "field",
                "cwd"
            ]
        );
    }

    #[test]
    fn config_keys_are_camel_case() {
        let keys = names_of::<GuardrailConfig>();
        assert!(keys.contains(&"extraRules"));
        assert!(keys.contains(&"changeWindowFiles"));
        assert_eq!(keys.len(), 8);
    }

    #[test]
    fn drift_names_each_side() {
        assert!(drift(&schema()).is_empty());
        let mut other = schema();
        other["rule"].as_array_mut().unwrap().retain(|v| v != "cwd");
        other["rule"].as_array_mut().unwrap().push("owner".into());
        let d = drift(&other);
        assert_eq!(d.len(), 2, "{d:?}");
        assert!(d[0].starts_with("rule.cwd: accepted by guardrail"));
        assert!(d[1].starts_with("rule.owner: on the other side"));
    }

    #[test]
    fn every_builtin_action_is_listed() {
        assert_eq!(
            schema()["actions"],
            json!([
                "check",
                "inputLimit",
                "searchNudge",
                "searchAdvise",
                "mintAdvise",
                "exec"
            ])
        );
    }
}
