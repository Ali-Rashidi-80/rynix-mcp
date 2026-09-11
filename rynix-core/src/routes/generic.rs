use regex::Regex;
use std::path::{Path, PathBuf};

use crate::models::{ApiRoute, ScanConfig};

/// Cross-framework heuristic route extraction (Tier 2/3 fallback).
pub fn extract_generic_routes(repo: &Path, config: &ScanConfig) -> Vec<ApiRoute> {
    let mut routes = Vec::new();
    let patterns: Vec<(Regex, &str)> = vec![
        (
            Regex::new(r#"\.(get|post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]"#).unwrap(),
            "express",
        ),
        (
            Regex::new(r#"@(Get|Post|Put|Patch|Delete)Mapping\s*\(\s*["']([^"']+)["']"#).unwrap(),
            "spring",
        ),
        (
            Regex::new(r#"\[Http(Get|Post|Put|Patch|Delete)\s*\(\s*["']([^"']+)["']"#).unwrap(),
            "aspnet",
        ),
        (
            Regex::new(r#"Route::(get|post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]"#).unwrap(),
            "laravel",
        ),
    ];

    let mut roots: Vec<PathBuf> = config
        .api_roots
        .iter()
        .map(|r| repo.join(r))
        .filter(|p| p.is_dir())
        .collect();
    if roots.is_empty() {
        roots.push(repo.to_path_buf());
    }

    for root in roots {
        for entry in walkdir::WalkDir::new(&root)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !matches!(ext, "js" | "ts" | "java" | "cs" | "php" | "go" | "rb" | "rs") {
                continue;
            }
            let rel = path
                .strip_prefix(repo)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            for (line_no, line) in content.lines().enumerate() {
                for (re, _framework) in &patterns {
                    for cap in re.captures_iter(line) {
                        let method = cap.get(1).map(|m| m.as_str().to_uppercase()).unwrap_or_default();
                        let route_path = cap.get(2).map(|m| m.as_str()).unwrap_or("/").to_string();
                        let idor_risk_score = if route_path.contains('{') { 70 } else { 20 };
                        routes.push(ApiRoute {
                            method,
                            path: route_path,
                            file: rel.clone(),
                            line: (line_no + 1) as u32,
                            handler: None,
                            auth_required: line.contains("auth") || line.contains("Auth"),
                            auth_hint: None,
                            idor_risk_score,
                        });
                    }
                }
            }
        }
    }
    routes
}
