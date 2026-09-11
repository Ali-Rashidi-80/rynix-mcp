use regex::Regex;
use std::path::Path;

use crate::models::{ApiRoute, ScanConfig};

use super::common::{push_regex_matches, source_roots, walk_files};

pub fn extract_aspnet_routes(repo: &Path, config: &ScanConfig) -> Vec<ApiRoute> {
    let roots = source_roots(repo, config);
    let files = walk_files(repo, &roots, &["cs"]);
    let re = Regex::new(
        r#"\[Http(Get|Post|Put|Patch|Delete)\s*\(\s*["']([^"']+)["']"#,
    )
    .unwrap();
    let mut routes = Vec::new();
    for (_path, rel) in files {
        let content = std::fs::read_to_string(repo.join(&rel)).unwrap_or_default();
        push_regex_matches(&mut routes, &content, &rel, &re, "GET", &config.auth_markers);
    }
    routes
}
