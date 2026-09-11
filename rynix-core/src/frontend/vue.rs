use regex::Regex;
use std::path::Path;

use crate::models::FrontendRoute;

pub fn extract(repo: &Path, root: &Path) -> Vec<FrontendRoute> {
    let mut routes = Vec::new();
    if !root.is_dir() {
        return routes;
    }

    let path_re = Regex::new(r#"path:\s*['"]([^'"]+)['"]"#).unwrap();
    let name_re = Regex::new(r#"name:\s*['"]([^'"]+)['"]"#).unwrap();

    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|x| x == "vue" || x == "ts" || x == "js")
        })
    {
        let path = entry.path();
        let rel = path
            .strip_prefix(repo)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let content = std::fs::read_to_string(path).unwrap_or_default();
        if !content.contains("createRouter") && !content.contains("routes:") && !path.extension().is_some_and(|x| x == "vue") {
            continue;
        }
        for (idx, line) in content.lines().enumerate() {
            if let Some(cap) = path_re.captures(line) {
                let route_path = cap.get(1).map(|m| m.as_str()).unwrap_or("/").to_string();
                routes.push(FrontendRoute {
                    path: route_path,
                    file: rel.clone(),
                    line: (idx + 1) as u32,
                });
            } else if let Some(cap) = name_re.captures(line) {
                let name = cap.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
                if !name.is_empty() {
                    routes.push(FrontendRoute {
                        path: format!("/{}", name),
                        file: rel.clone(),
                        line: (idx + 1) as u32,
                    });
                }
            }
        }
    }
    routes
}
