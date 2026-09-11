use regex::Regex;
use std::path::Path;

use crate::models::{ApiRoute, ScanConfig};

use super::common::{push_regex_matches, source_roots, walk_files};

pub fn extract_actix_routes(repo: &Path, config: &ScanConfig) -> Vec<ApiRoute> {
    let attr_re = Regex::new(r#"#\[(get|post|put|patch|delete)\(\s*"([^"]+)"#).unwrap();
    let chain_re =
        Regex::new(r#"web::(get|post|put|patch|delete)\(\s*"([^"]+)"\)\s*\.\s*to\("#).unwrap();
    let route_re =
        Regex::new(r#"\.route\(\s*"([^"]+)"\s*,\s*web::(get|post|put|patch|delete)\("#).unwrap();
    let res_re =
        Regex::new(r#"web::resource\(\s*"([^"]+)"\)\s*\.\s*route\(\s*web::(get|post|put|patch|delete)\("#).unwrap();

    let roots = source_roots(repo, config);
    let files = walk_files(repo, &roots, &["rs"]);
    let mut routes = Vec::new();
    for (_path, rel) in files {
        let content = std::fs::read_to_string(repo.join(&rel)).unwrap_or_default();
        if !content.contains("actix") && !content.contains("web::") && !content.contains("#[") {
            continue;
        }
        push_regex_matches(&mut routes, &content, &rel, &attr_re, "GET", &config.auth_markers);
        push_regex_matches(&mut routes, &content, &rel, &chain_re, "GET", &config.auth_markers);

        for (idx, line) in content.lines().enumerate() {
            for cap in route_re.captures_iter(line) {
                let path = cap.get(1).map(|m| m.as_str()).unwrap_or("/").to_string();
                let method = cap.get(2).map(|m| m.as_str().to_uppercase()).unwrap_or_else(|| "GET".to_string());
                let (auth_required, auth_hint) = super::common::auth_from_line(line, &config.auth_markers);
                let idor = super::common::idor_score(&path, auth_required);
                routes.push(ApiRoute {
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
            for cap in res_re.captures_iter(line) {
                let path = cap.get(1).map(|m| m.as_str()).unwrap_or("/").to_string();
                let method = cap.get(2).map(|m| m.as_str().to_uppercase()).unwrap_or_else(|| "GET".to_string());
                let (auth_required, auth_hint) = super::common::auth_from_line(line, &config.auth_markers);
                let idor = super::common::idor_score(&path, auth_required);
                routes.push(ApiRoute {
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
