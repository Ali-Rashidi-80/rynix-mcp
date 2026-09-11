use regex::Regex;
use std::path::Path;

use crate::models::{ApiRoute, ScanConfig};

use super::common::{source_roots, walk_files};

pub fn extract_rails_routes(repo: &Path, config: &ScanConfig) -> Vec<ApiRoute> {
    let roots = source_roots(repo, config);
    let files = walk_files(repo, &roots, &["rb"]);
    let re = Regex::new(r#"^\s*(get|post|put|patch|delete)\s+['"](/[^'"]*)['"]"#).unwrap();
    let mut routes = Vec::new();
    for (_path, rel) in files {
        let content = std::fs::read_to_string(repo.join(&rel)).unwrap_or_default();
        for (idx, line) in content.lines().enumerate() {
            if !line.contains("routes") && !content.contains("Rails.application") {
                continue;
            }
            for cap in re.captures_iter(line) {
                let method = cap.get(1).map(|m| m.as_str().to_uppercase()).unwrap_or_default();
                let route_path = cap.get(2).map(|m| m.as_str()).unwrap_or("/").to_string();
                let (auth_required, auth_hint) = super::common::auth_from_line(line, &config.auth_markers);
                let auth_required = auth_required || line.contains("authenticate");
                let idor = super::common::idor_score(&route_path, auth_required);
                routes.push(ApiRoute {
                    method,
                    path: route_path,
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
