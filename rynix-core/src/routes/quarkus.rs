use regex::Regex;
use std::path::Path;

use crate::models::ScanConfig;

use super::common::{auth_from_line, idor_score, source_roots, walk_files};

pub fn extract_quarkus_routes(repo: &Path, config: &ScanConfig) -> Vec<crate::models::ApiRoute> {
    let path_re = Regex::new(r#"@Path\s*\(\s*"([^"]+)"\s*\)"#).unwrap();
    let method_re = Regex::new(r#"@(GET|POST|PUT|PATCH|DELETE)"#).unwrap();
    let roots = source_roots(repo, config);
    let files = walk_files(repo, &roots, &["java", "kt"]);
    let mut routes = Vec::new();
    for (_path, rel) in files {
        let content = std::fs::read_to_string(repo.join(&rel)).unwrap_or_default();
        let mut current_path = String::new();
        for (idx, line) in content.lines().enumerate() {
            if let Some(cap) = path_re.captures(line) {
                current_path = cap.get(1).map(|m| m.as_str()).unwrap_or("/").to_string();
            }
            if let Some(cap) = method_re.captures(line) {
                let method = cap.get(1).map(|m| m.as_str()).unwrap_or("GET").to_string();
                let path = if current_path.is_empty() { "/".into() } else { current_path.clone() };
                let (auth_required, auth_hint) = auth_from_line(line, &config.auth_markers);
                routes.push(crate::models::ApiRoute {
                    method,
                    path,
                    file: rel.clone(),
                    line: (idx + 1) as u32,
                    handler: None,
                    auth_required,
                    auth_hint,
                    idor_risk_score: idor_score(&current_path, auth_required),
                });
            }
        }
    }
    routes
}
