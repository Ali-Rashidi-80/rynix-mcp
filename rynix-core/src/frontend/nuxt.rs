use regex::Regex;
use std::path::Path;

use crate::models::FrontendRoute;

pub fn extract(repo: &Path, root: &Path) -> Vec<FrontendRoute> {
    let mut routes = Vec::new();
    if !root.is_dir() {
        return routes;
    }

    let pages_re =
        Regex::new(r#"pages/(.+)\.(vue|tsx|jsx|ts|js)$"#).expect("nuxt pages re");

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
        if let Some(cap) = pages_re.captures(&rel) {
            let segments = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let route_path = if segments == "index" {
                "/".to_string()
            } else {
                format!(
                    "/{}",
                    segments
                        .replace("/index", "")
                        .replace("index", "")
                        .replace("[", "{")
                        .replace("]", "}")
                )
            };
            routes.push(FrontendRoute {
                path: route_path,
                file: rel.clone(),
                line: 1,
            });
        }
    }
    routes
}
