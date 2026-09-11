use regex::Regex;
use std::path::Path;

use crate::models::{ApiRoute, ScanConfig};

use super::common::{source_roots, walk_files};

pub fn extract_django_routes(repo: &Path, config: &ScanConfig) -> Vec<ApiRoute> {
    let roots = source_roots(repo, config);
    let files = walk_files(repo, &roots, &["py"]);
    let path_re = Regex::new(r#"(?:path|re_path|url)\s*\(\s*r?['"]([^'"]+)['"]"#).unwrap();
    let mut routes = Vec::new();
    for (_path, rel) in files {
        let content = std::fs::read_to_string(repo.join(&rel)).unwrap_or_default();
        if !content.contains("path(") && !content.contains("re_path(") && !content.contains("url(") {
            continue;
        }
        for (idx, line) in content.lines().enumerate() {
            for cap in path_re.captures_iter(line) {
                let route_path = cap.get(1).map(|m| m.as_str()).unwrap_or("/").to_string();
                let (auth_required, auth_hint) = super::common::auth_from_line(line, &config.auth_markers);
                let auth_required = auth_required
                    || line.contains("LoginRequired")
                    || line.contains("permission_classes");
                let idor = super::common::idor_score(&route_path, auth_required);
                routes.push(ApiRoute {
                    method: "GET".to_string(),
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
