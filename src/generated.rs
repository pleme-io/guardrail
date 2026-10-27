use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use crate::hook::HookInput;

pub const RULE: &str = "generated-tree";

const EDIT_TOOLS: [&str; 4] = ["Edit", "Write", "MultiEdit", "NotebookEdit"];
const RENDERED: [&str; 3] = ["services", "workloads", "generated"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    pub kind: String,
    pub name: String,
    pub output: String,
}

#[must_use]
pub fn trees(project: &Value) -> Vec<Tree> {
    RENDERED
        .iter()
        .filter_map(|kind| project.get(*kind)?.as_object().map(|m| (kind, m)))
        .flat_map(|(kind, entries)| {
            entries.iter().filter_map(move |(name, spec)| {
                let output = spec.get("output")?.as_str()?.trim_end_matches('/');
                (!output.is_empty()).then(|| Tree {
                    kind: (*kind).to_string(),
                    name: name.clone(),
                    output: output.to_string(),
                })
            })
        })
        .collect()
}

#[must_use]
pub fn bluefile_above(file: &Path) -> Option<PathBuf> {
    file.ancestors()
        .skip(1)
        .map(|dir| dir.join("Bluefile"))
        .find(|b| b.is_file())
}

#[must_use]
pub fn owner<'a>(file: &Path, root: &Path, trees: &'a [Tree]) -> Option<&'a Tree> {
    let rel = file.strip_prefix(root).ok()?;
    trees.iter().find(|t| rel.starts_with(&t.output))
}

fn blue_project(bluefile: &Path) -> Option<Value> {
    let out = Command::new("blue")
        .args(["bluefile", "--json"])
        .arg(bluefile)
        .current_dir(bluefile.parent()?)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    serde_json::from_slice(&out.stdout).ok()
}

fn edited_file(input: &HookInput) -> Option<PathBuf> {
    if !EDIT_TOOLS.contains(&input.tool_name.as_deref()?) {
        return None;
    }
    let file = PathBuf::from(input.tool_input.as_ref()?.file_path.as_deref()?);
    if file.is_absolute() {
        Some(file)
    } else {
        Some(PathBuf::from(input.cwd.as_deref()?).join(file))
    }
}

#[must_use]
pub fn block_with(
    input: &HookInput,
    project: &dyn Fn(&Path) -> Option<Value>,
) -> Option<(String, String)> {
    let file = edited_file(input)?;
    let bluefile = bluefile_above(&file)?;
    let root = bluefile.parent()?;
    let trees = trees(&project(&bluefile)?);
    let tree = owner(&file, root, &trees)?;
    let kind = tree.kind.trim_end_matches('s');
    Some((
        RULE.to_string(),
        format!(
            "{} is rendered from {kind}(\"{}\") in {}, so a hand edit is overwritten and fails `{kind}-{}-fresh`. Change the Bluefile or the blue program it lowers, then run `nix run .#regen` in {}.",
            file.display(),
            tree.name,
            bluefile.display(),
            tree.name,
            root.display(),
        ),
    ))
}

#[must_use]
pub fn block(input: &HookInput) -> Option<(String, String)> {
    block_with(input, &blue_project)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hook::ToolInput;
    use serde_json::json;

    fn project() -> Value {
        json!({
            "name": "kensa-service",
            "services": {"kensa": {"output": "deploy/kensa", "port": 8080}},
            "workloads": {"web": {"output": "deploy/web.yaml"}},
            "generated": {"catalog": {"output": "docs/CATALOG.md"}}
        })
    }

    fn edit(tool: &str, path: &Path) -> HookInput {
        HookInput {
            tool_name: Some(tool.to_string()),
            tool_input: Some(ToolInput {
                file_path: Some(path.display().to_string()),
                ..ToolInput::default()
            }),
            cwd: None,
        }
    }

    fn repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Bluefile"), "package(\"x\", \"0.1.0\")\n").unwrap();
        dir
    }

    #[test]
    fn every_rendered_collection_names_its_output() {
        let t = trees(&project());
        let outputs: Vec<&str> = t.iter().map(|t| t.output.as_str()).collect();
        assert_eq!(
            outputs,
            ["deploy/kensa", "deploy/web.yaml", "docs/CATALOG.md"]
        );
    }

    #[test]
    fn an_edit_inside_a_service_tree_is_blocked_and_names_the_bluefile() {
        let dir = repo();
        let file = dir.path().join("deploy/kensa/chart/values.yaml");
        let (rule, why) = block_with(&edit("Edit", &file), &|_| Some(project())).unwrap();
        assert_eq!(rule, RULE);
        assert!(why.contains("service(\"kensa\")"), "{why}");
        assert!(why.contains("nix run .#regen"), "{why}");
    }

    #[test]
    fn a_write_to_a_rendered_file_is_blocked() {
        let dir = repo();
        let file = dir.path().join("deploy/web.yaml");
        assert!(block_with(&edit("Write", &file), &|_| Some(project())).is_some());
    }

    #[test]
    fn a_sibling_that_only_shares_a_prefix_is_not_blocked() {
        let dir = repo();
        let file = dir.path().join("deploy/kensa-notes.md");
        assert!(block_with(&edit("Edit", &file), &|_| Some(project())).is_none());
    }

    #[test]
    fn the_bluefile_and_sources_stay_editable() {
        let dir = repo();
        for rel in ["Bluefile", "src/main.rs", "examples/attestations.b"] {
            let file = dir.path().join(rel);
            assert!(
                block_with(&edit("Edit", &file), &|_| Some(project())).is_none(),
                "{rel}"
            );
        }
    }

    #[test]
    fn a_read_or_a_repo_with_no_bluefile_passes() {
        let dir = repo();
        let file = dir.path().join("deploy/kensa/chart/values.yaml");
        assert!(block_with(&edit("Read", &file), &|_| Some(project())).is_none());
        let bare = tempfile::tempdir().unwrap();
        let file = bare.path().join("deploy/kensa/chart/values.yaml");
        assert!(block_with(&edit("Edit", &file), &|_| Some(project())).is_none());
    }

    #[test]
    fn an_unreadable_bluefile_does_not_block() {
        let dir = repo();
        let file = dir.path().join("deploy/kensa/chart/values.yaml");
        assert!(block_with(&edit("Edit", &file), &|_| None).is_none());
    }
}
