use regex::Regex;
use std::path::Path;

use crate::models::FrontendRoute;

pub fn extract(repo: &Path, root: &Path) -> Vec<FrontendRoute> {
    let mut routes = Vec::new();
    if !root.is_dir() {
        return routes;
    }

    let route_file_re =
        Regex::new(r#"routes/(.+)/\+page\.(svelte|ts|js)$"#).expect("sveltekit route re");
    let route_ts_re = Regex::new(r#"['"]([^'"]+)['"]\s*:\s*\w+"#).unwrap();

    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        let rel = path
            .strip_prefix(repo)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");

        if let Some(cap) = route_file_re.captures(&rel) {
            let segments = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let route_path = if segments.is_empty() {
                "/".to_string()
            } else {
                format!("/{}", segments.replace('[', "{").replace(']', "}"))
            };
            routes.push(FrontendRoute {
                path: route_path,
                file: rel.clone(),
                line: 1,
            });
            continue;
        }

        if rel.ends_with("+page.svelte") || rel.ends_with("+page.ts") {
            let parent = path.parent().unwrap_or(path);
            let route_path = parent
                .file_name()
                .map(|n| format!("/{}", n.to_string_lossy()))
                .unwrap_or_else(|| "/".to_string());
            routes.push(FrontendRoute {
                path: route_path,
                file: rel.clone(),
                line: 1,
            });
        }

        if rel.contains("routes") && rel.ends_with(".ts") {
            let content = std::fs::read_to_string(path).unwrap_or_default();
            for (idx, line) in content.lines().enumerate() {
                if line.contains("path") {
                    if let Some(cap) = route_ts_re.captures(line) {
                        routes.push(FrontendRoute {
                            path: cap.get(1).map(|m| m.as_str()).unwrap_or("/").to_string(),
                            file: rel.clone(),
                            line: (idx + 1) as u32,
                        });
                    }
                }
            }
        }
    }
    routes
}
