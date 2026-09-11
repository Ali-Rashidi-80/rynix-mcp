use regex::Regex;
use std::path::Path;

use crate::models::{ApiRoute, ScanConfig};

use crate::routes::common::{source_roots, walk_files};

pub fn extract_trpc_routes(repo: &Path, config: &ScanConfig) -> Vec<ApiRoute> {
    let roots = source_roots(repo, config);
    let files = walk_files(repo, &roots, &["ts", "js"]);
    let proc_re = Regex::new(r#"\.(query|mutation|subscription)\s*\(\s*['"]?([^'")\s]*)"#).unwrap();
    let router_re = Regex::new(r#"createTRPCRouter\s*\(\s*\{([^}]+)\}"#).unwrap();
    let mut routes = Vec::new();

    for (_path, rel) in files {
        let content = std::fs::read_to_string(repo.join(&rel)).unwrap_or_default();
        if !content.contains("trpc") && !content.contains("TRPC") {
            continue;
        }
        for (idx, line) in content.lines().enumerate() {
            for cap in proc_re.captures_iter(line) {
                let kind = cap.get(1).map(|m| m.as_str().to_uppercase()).unwrap_or_default();
                let name = cap.get(2).map(|m| m.as_str()).unwrap_or("").to_string();
                let path = if name.is_empty() {
                    format!("/trpc/{}", kind.to_lowercase())
                } else {
                    format!("/trpc/{}.{}", name, kind.to_lowercase())
                };
                let method = if kind == "QUERY" { "GET" } else { "POST" };
                routes.push(ApiRoute {
                    method: method.to_string(),
                    path,
                    file: rel.clone(),
                    line: (idx + 1) as u32,
                    handler: Some(name),
                    auth_required: line.contains("protectedProcedure") || line.contains("auth"),
                    auth_hint: None,
                    idor_risk_score: 55,
                });
            }
        }
        for cap in router_re.captures_iter(&content) {
            if let Some(block) = cap.get(1) {
                for key in block.as_str().split(',') {
                    let proc = key.split(':').next().unwrap_or("").trim();
                    if !proc.is_empty() {
                        routes.push(ApiRoute {
                            method: "POST".to_string(),
                            path: format!("/trpc/{}", proc),
                            file: rel.clone(),
                            line: 1,
                            handler: Some(proc.to_string()),
                            auth_required: block.as_str().contains("protectedProcedure"),
                            auth_hint: None,
                            idor_risk_score: 55,
                        });
                    }
                }
            }
        }
    }
    routes
}
