use regex::Regex;
use std::path::Path;

use crate::models::FrontendRoute;

pub fn extract(repo: &Path, root: &Path) -> Vec<FrontendRoute> {
    let mut routes = Vec::new();
    if !root.is_dir() {
        return routes;
    }

    let path_re = Regex::new(r#"path:\s*['"]([^'"]+)['"]"#).unwrap();
    let load_children_re = Regex::new(r#"loadChildren:\s*\(\)\s*=>"#).unwrap();

    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|x| x == "ts" || x == "js")
        })
    {
        let path = entry.path();
        let rel = path
            .strip_prefix(repo)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let content = std::fs::read_to_string(path).unwrap_or_default();
        if !content.contains("Routes") && !content.contains("RouterModule") && !load_children_re.is_match(&content) {
            continue;
        }
        for (idx, line) in content.lines().enumerate() {
            if let Some(cap) = path_re.captures(line) {
                routes.push(FrontendRoute {
                    path: cap.get(1).map(|m| m.as_str()).unwrap_or("/").to_string(),
                    file: rel.clone(),
                    line: (idx + 1) as u32,
                });
            }
        }
    }
    routes
}
