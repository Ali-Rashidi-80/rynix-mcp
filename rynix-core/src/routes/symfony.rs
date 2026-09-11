use regex::Regex;
use std::path::Path;

use crate::models::ScanConfig;

use super::common::{auth_from_line, idor_score, source_roots, walk_files};

pub fn extract_symfony_routes(repo: &Path, config: &ScanConfig) -> Vec<crate::models::ApiRoute> {
    let re = Regex::new(r#"#\[Route\s*\(\s*['"]([^'"]+)['"]"#).unwrap();
    let roots = source_roots(repo, config);
    let files = walk_files(repo, &roots, &["php"]);
    let mut routes = Vec::new();
    for (_path, rel) in files {
        let content = std::fs::read_to_string(repo.join(&rel)).unwrap_or_default();
        for (idx, line) in content.lines().enumerate() {
            for cap in re.captures_iter(line) {
                let path = cap.get(1).map(|m| m.as_str()).unwrap_or("/").to_string();
                let (auth_required, auth_hint) = auth_from_line(line, &config.auth_markers);
                routes.push(crate::models::ApiRoute {
                    method: "GET".into(),
                    path,
                    file: rel.clone(),
                    line: (idx + 1) as u32,
                    handler: None,
                    auth_required,
                    auth_hint,
                    idor_risk_score: idor_score(&cap.get(1).map(|m| m.as_str()).unwrap_or("/"), auth_required),
                });
            }
        }
    }
    routes
}
