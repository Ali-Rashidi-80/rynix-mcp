use regex::Regex;
use std::path::Path;

use crate::models::{ApiRoute, ScanConfig};

use super::common::{source_roots, walk_files};

pub fn extract_flask_routes(repo: &Path, config: &ScanConfig) -> Vec<ApiRoute> {
    let roots = source_roots(repo, config);
    let files = walk_files(repo, &roots, &["py"]);
    let route_re =
        Regex::new(r#"@(?:app|bp|blueprint|\w+_bp)\.route\s*\(\s*['"]([^'"]+)['"]"#).unwrap();
    let methods_re = Regex::new(r#"methods\s*=\s*\[([^\]]+)\]"#).unwrap();
    let mut routes = Vec::new();
    for (_path, rel) in files {
        let content = std::fs::read_to_string(repo.join(&rel)).unwrap_or_default();
        for (idx, line) in content.lines().enumerate() {
            if let Some(cap) = route_re.captures(line) {
                let route_path = cap.get(1).map(|m| m.as_str()).unwrap_or("/").to_string();
                let methods: Vec<String> = methods_re
                    .captures(line)
                    .map(|c| {
                        c.get(1)
                            .map(|m| m.as_str())
                            .unwrap_or("GET")
                            .split(',')
                            .map(|s| s.trim().trim_matches('"').trim_matches('\'').to_uppercase())
                            .filter(|s| !s.is_empty())
                            .collect()
                    })
                    .unwrap_or_else(|| vec!["GET".to_string()]);
                let (auth_required, auth_hint) = super::common::auth_from_line(line, &config.auth_markers);
                let auth_required = auth_required || line.contains("login_required");
                for method in methods {
                    routes.push(ApiRoute {
                        method,
                        path: route_path.clone(),
                        file: rel.clone(),
                        line: (idx + 1) as u32,
                        handler: None,
                        auth_required,
                        auth_hint: auth_hint.clone(),
                        idor_risk_score: super::common::idor_score(&route_path, auth_required),
                    });
                }
            }
        }
    }
    routes
}
