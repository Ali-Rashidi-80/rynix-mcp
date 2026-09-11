use regex::Regex;
use std::path::Path;

use crate::models::FrontendRoute;

pub fn extract(repo: &Path, root: &Path) -> Vec<FrontendRoute> {
    let mut routes = Vec::new();
    if !root.is_dir() {
        return routes;
    }

    let app_page_re = Regex::new(r#"(?:app|pages)/([^/]+(?:/[^/]+)*)/page\.(tsx|jsx|ts|js)$"#)
        .expect("app page re");
    let route_export_re =
        Regex::new(r#"export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)"#).unwrap();

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

        if let Some(cap) = app_page_re.captures(&rel) {
            let segments = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let route_path = if segments.is_empty() || segments == "page" {
                "/".to_string()
            } else {
                format!("/{}", segments.replace("(auth)", "").replace("(public)", ""))
            };
            routes.push(FrontendRoute {
                path: route_path,
                file: rel.clone(),
                line: 1,
            });
            continue;
        }

        if rel.contains("/pages/") && (rel.ends_with(".tsx") || rel.ends_with(".jsx")) {
            let page_path = rel.split("/pages/").nth(1).unwrap_or("");
            if page_path.contains('.') {
                let without_ext = page_path.rsplit_once('.').map(|(p, _)| p).unwrap_or(page_path);
                let route_path = if without_ext == "index" {
                    "/".to_string()
                } else {
                    format!("/{}", without_ext.replace("/index", "").replace("index", ""))
                };
                routes.push(FrontendRoute {
                    path: route_path,
                    file: rel.clone(),
                    line: 1,
                });
            }
        }

        if rel.ends_with("route.ts") || rel.ends_with("route.js") {
            let content = std::fs::read_to_string(path).unwrap_or_default();
            for (idx, line) in content.lines().enumerate() {
                if route_export_re.is_match(line) {
                    let api_path = rel
                        .split("/app/")
                        .nth(1)
                        .map(|p| format!("/{}", p.replace("/route.ts", "").replace("/route.js", "")))
                        .unwrap_or_else(|| rel.clone());
                    routes.push(FrontendRoute {
                        path: api_path,
                        file: rel.clone(),
                        line: (idx + 1) as u32,
                    });
                }
            }
        }
    }
    routes
}
