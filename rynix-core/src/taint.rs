use std::path::{Path, PathBuf};

use tree_sitter::{Node, Parser, Tree};
use tree_sitter_python::LANGUAGE;
use walkdir::WalkDir;

use crate::models::{prune_nested_roots, ScanConfig, TaintHint};

const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    "target",
    ".next",
    "backups",
];

const SINK_NAMES: &[&str] = &[
    "eval",
    "exec",
    "compile",
    "system",
    "popen",
    "run",
    "call",
    "execute",
    "executemany",
];

fn should_skip(path: &Path) -> bool {
    path.components().any(|c| {
        let s = c.as_os_str().to_string_lossy();
        SKIP_DIRS.iter().any(|skip| s == *skip)
    })
}

fn node_text(node: &Node, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or("").trim().to_string()
}

fn line_of(node: &Node) -> u32 {
    node.start_position().row as u32 + 1
}

fn is_string_literal(node: &Node, source: &[u8]) -> bool {
    match node.kind() {
        "string" | "concatenated_string" => true,
        "call" => {
            let func = node.child_by_field_name("function");
            func.map(|f| f.kind() == "attribute" && node_text(&f, source).ends_with("join"))
                .unwrap_or(false)
        }
        _ => false,
    }
}

fn first_arg_is_dynamic(call: &Node, source: &[u8]) -> bool {
    let args = call.child_by_field_name("arguments");
    if args.is_none() {
        return false;
    }
    let args = args.unwrap();
    let mut cursor = args.walk();
    for child in args.children(&mut cursor) {
        if !child.is_named() {
            continue;
        }
        return !is_string_literal(&child, source);
    }
    false
}

fn sink_name_from_call(call: &Node, source: &[u8]) -> Option<String> {
    let func = call.child_by_field_name("function")?;
    let name = match func.kind() {
        "identifier" => Some(node_text(&func, source)),
        "attribute" => node_text(&func, source)
            .split('.')
            .last()
            .map(|s| s.to_string()),
        _ => None,
    }?;
    if SINK_NAMES.iter().any(|s| name == *s) {
        Some(name)
    } else {
        None
    }
}

fn scan_tree(tree: &Tree, source: &[u8], rel: &str, hints: &mut Vec<TaintHint>) {
    let root = tree.root_node();
    let mut cursor = root.walk();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "call" {
            if let Some(sink) = sink_name_from_call(&node, source) {
                if first_arg_is_dynamic(&node, source) {
                    hints.push(TaintHint {
                        file: rel.to_string(),
                        line: line_of(&node),
                        sink: sink.clone(),
                        severity: "high".into(),
                        rule_id: "RYNIX-TAINT-SINK".into(),
                        snippet: node_text(&node, source).chars().take(120).collect(),
                    });
                }
            }
        }
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
        cursor = node.walk();
    }
}

pub fn scan_taint(repo: &Path, config: &ScanConfig) -> Vec<TaintHint> {
    let mut hints = Vec::new();
    let mut parser = Parser::new();
    if parser.set_language(&LANGUAGE.into()).is_err() {
        return hints;
    }

    let roots: Vec<PathBuf> = prune_nested_roots(&config.api_roots)
        .iter()
        .map(|r| repo.join(r))
        .filter(|p| p.is_dir())
        .collect();
    let scan_roots: Vec<&Path> = if roots.is_empty() {
        vec![repo]
    } else {
        roots.iter().map(|p| p.as_path()).collect()
    };

    for root in scan_roots {
        for entry in WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if !path.is_file() || should_skip(path) {
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("py") {
                continue;
            }
            let meta = match std::fs::metadata(path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.len() > 512_000 {
                continue;
            }
            let source = match std::fs::read(path) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let tree = match parser.parse(&source, None) {
                Some(t) => t,
                None => continue,
            };
            let rel = path
                .strip_prefix(repo)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            scan_tree(&tree, &source, &rel, &mut hints);
        }
    }
    hints
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    #[test]
    fn literal_eval_in_function_not_flagged() {
        let mut parser = Parser::new();
        parser.set_language(&LANGUAGE.into()).unwrap();
        let source = b"def ok():\n    eval(\"1+1\")\n";
        let tree = parser.parse(source, None).unwrap();
        let mut hints = Vec::new();
        scan_tree(&tree, source, "safe.py", &mut hints);
        assert!(hints.is_empty(), "hints: {:?}", hints);
    }
}
