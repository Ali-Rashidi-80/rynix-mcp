use regex::Regex;
use std::path::Path;

use crate::models::{ApiRoute, ScanConfig};

use crate::routes::common::{source_roots, walk_files};

pub fn extract_graphql_routes(repo: &Path, config: &ScanConfig) -> Vec<ApiRoute> {
    let roots = source_roots(repo, config);
    let files = walk_files(repo, &roots, &["graphql", "gql", "ts", "js", "py", "rs"]);
    let field_re = Regex::new(r#"(?:type\s+Query|type\s+Mutation)\s*\{([^}]+)\}"#).unwrap();
    let op_re = Regex::new(r"(\w+)\s*:\s*[\w\[\]!]+").unwrap();
    let mount_re = Regex::new(r#"(?:/graphql|graphqlPath|GRAPHQL_ENDPOINT)\s*[=:]\s*['"]([^'"]+)['"]"#).unwrap();
    let mut routes = Vec::new();

    for (_path, rel) in files {
        let content = std::fs::read_to_string(repo.join(&rel)).unwrap_or_default();
        for cap in mount_re.captures_iter(&content) {
            let path = cap.get(1).map(|m| m.as_str()).unwrap_or("/graphql").to_string();
            routes.push(ApiRoute {
                method: "POST".to_string(),
                path,
                file: rel.clone(),
                line: 1,
                handler: Some("graphql".into()),
                auth_required: content.contains("auth") || content.contains("context"),
                auth_hint: None,
                idor_risk_score: 50,
            });
        }
        for cap in field_re.captures_iter(&content) {
            if let Some(block) = cap.get(1) {
                for fcap in op_re.captures_iter(block.as_str()) {
                    if let Some(field) = fcap.get(1) {
                        let name = field.as_str();
                        if matches!(name, "type" | "Query" | "Mutation") {
                            continue;
                        }
                        routes.push(ApiRoute {
                            method: "POST".to_string(),
                            path: format!("/graphql#{}", name),
                            file: rel.clone(),
                            line: 1,
                            handler: Some(name.to_string()),
                            auth_required: block.as_str().contains("auth"),
                            auth_hint: None,
                            idor_risk_score: 45,
                        });
                    }
                }
            }
        }
    }
    routes
}
