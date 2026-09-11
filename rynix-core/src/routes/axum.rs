use regex::Regex;
use std::path::Path;

use crate::models::ScanConfig;

use super::common::{auth_from_line, idor_score, source_roots, walk_files};

pub fn extract_axum_routes(repo: &Path, config: &ScanConfig) -> Vec<crate::models::ApiRoute> {
    let re = Regex::new(
        r#"\.route\s*\(\s*["']([^"']+)["']\s*,\s*(?:[\w:]+::)*(get|post|put|patch|delete)"#,
    )
    .unwrap();
    let roots = source_roots(repo, config);
    let files = walk_files(repo, &roots, &["rs"]);
    let mut routes = Vec::new();
    for (_path, rel) in files {
        let content = std::fs::read_to_string(repo.join(&rel)).unwrap_or_default();
        for (idx, line) in content.lines().enumerate() {
            for cap in re.captures_iter(line) {
                let path = cap.get(1).map(|m| m.as_str()).unwrap_or("/").to_string();
                let method = cap
                    .get(2)
                    .map(|m| m.as_str().to_uppercase())
                    .unwrap_or_else(|| "GET".into());
                let (auth_required, auth_hint) = auth_from_line(line, &config.auth_markers);
                let idor = idor_score(&path, auth_required);
                routes.push(crate::models::ApiRoute {
                    method,
                    path,
                    file: rel.clone(),
                    line: (idx + 1) as u32,
                    handler: None,
                    auth_required,
                    auth_hint,
                    idor_risk_score: idor,
                });
            }
        }
    }
    routes
}
