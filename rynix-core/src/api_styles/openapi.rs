use regex::Regex;
use std::path::Path;

use crate::models::{ApiRoute, ScanConfig};

pub fn extract_openapi_routes(repo: &Path, config: &ScanConfig) -> Vec<ApiRoute> {
    let mut routes = Vec::new();
    let candidates = [
        "openapi.json",
        "openapi.yaml",
        "openapi.yml",
        "swagger.json",
        "api/openapi.json",
        "docs/openapi.json",
    ];
    for rel in candidates {
        let path = repo.join(rel);
        if !path.is_file() {
            continue;
        }
        let content = std::fs::read_to_string(&path).unwrap_or_default();
        if rel.ends_with(".json") {
            routes.extend(parse_openapi_json(&content, rel));
        } else {
            routes.extend(parse_openapi_yaml(&content, rel));
        }
    }

    let roots: Vec<std::path::PathBuf> = config
        .api_roots
        .iter()
        .map(|r| repo.join(r))
        .filter(|p| p.is_dir())
        .collect();
    for root in roots {
        for entry in walkdir::WalkDir::new(&root)
            .max_depth(4)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let p = entry.path();
            let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            if !name.contains("openapi") && !name.contains("swagger") {
                continue;
            }
            if !name.ends_with(".yaml") && !name.ends_with(".yml") {
                continue;
            }
            let rel = p
                .strip_prefix(repo)
                .unwrap_or(p)
                .to_string_lossy()
                .replace('\\', "/");
            let content = std::fs::read_to_string(p).unwrap_or_default();
            routes.extend(parse_openapi_yaml(&content, &rel));
        }
    }
    routes
}

fn parse_openapi_json(content: &str, file: &str) -> Vec<ApiRoute> {
    let mut routes = Vec::new();
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(content) {
        if let Some(paths) = value.get("paths").and_then(|p| p.as_object()) {
            for (path, ops) in paths {
                if let Some(obj) = ops.as_object() {
                    for method in obj.keys() {
                        let m = method.to_uppercase();
                        if matches!(m.as_str(), "GET" | "POST" | "PUT" | "PATCH" | "DELETE") {
                            routes.push(ApiRoute {
                                method: m,
                                path: path.clone(),
                                file: file.to_string(),
                                line: 1,
                                handler: None,
                                auth_required: obj.get(method).and_then(|o| o.get("security")).is_some(),
                                auth_hint: Some("openapi".into()),
                                idor_risk_score: if path.contains('{') { 60 } else { 25 },
                            });
                        }
                    }
                }
            }
        }
    }
    routes
}

fn parse_openapi_yaml(content: &str, file: &str) -> Vec<ApiRoute> {
    let mut routes = Vec::new();
    let path_re = Regex::new(r#"^\s*(/[\w/{}\-._]+):\s*$"#).unwrap();
    let method_re = Regex::new(r"^\s+(get|post|put|patch|delete):").unwrap();
    let mut current_path = String::new();
    for line in content.lines() {
        if let Some(cap) = path_re.captures(line) {
            current_path = cap.get(1).map(|m| m.as_str()).unwrap_or("/").to_string();
        } else if let Some(cap) = method_re.captures(line) {
            let method = cap.get(1).map(|m| m.as_str().to_uppercase()).unwrap_or_default();
            if !current_path.is_empty() {
                routes.push(ApiRoute {
                    method,
                    path: current_path.clone(),
                    file: file.to_string(),
                    line: 1,
                    handler: None,
                    auth_required: line.contains("security") || content.contains("bearerAuth"),
                    auth_hint: Some("openapi".into()),
                    idor_risk_score: if current_path.contains('{') { 60 } else { 25 },
                });
            }
        }
    }
    routes
}
