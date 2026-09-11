use regex::Regex;
use std::path::Path;

use crate::models::{ApiRoute, ScanConfig};

use super::common::{source_roots, walk_files};

pub fn extract_nestjs_routes(repo: &Path, config: &ScanConfig) -> Vec<ApiRoute> {
    let roots = source_roots(repo, config);
    let files = walk_files(repo, &roots, &["ts", "js"]);
    let method_re = Regex::new(r#"@(Get|Post|Put|Patch|Delete|All)\s*\(\s*['"]?([^'")\s]*)"#).unwrap();
    let mut routes = Vec::new();
    for (_path, rel) in files {
        let content = std::fs::read_to_string(repo.join(&rel)).unwrap_or_default();
        for (idx, line) in content.lines().enumerate() {
            for cap in method_re.captures_iter(line) {
                let method = cap.get(1).map(|m| m.as_str().to_uppercase()).unwrap_or_default();
                let route_path = cap.get(2).map(|m| m.as_str()).unwrap_or("").to_string();
                let path = if route_path.is_empty() { "/" } else { route_path.as_str() };
                let (auth_required, auth_hint) = super::common::auth_from_line(line, &config.auth_markers);
                let auth_required = auth_required
                    || line.contains("UseGuards")
                    || line.contains("@Roles");
                routes.push(ApiRoute {
                    method,
                    path: path.to_string(),
                    file: rel.clone(),
                    line: (idx + 1) as u32,
                    handler: None,
                    auth_required,
                    auth_hint,
                    idor_risk_score: super::common::idor_score(path, auth_required),
                });
            }
        }
    }
    routes
}
