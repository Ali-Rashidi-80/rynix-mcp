use std::path::Path;

use crate::models::{ApiRoute, ScanConfig};

use super::common::extract_http_method_routes;

pub fn extract_adonisjs_routes(repo: &Path, config: &ScanConfig) -> Vec<ApiRoute> {
    extract_http_method_routes(
        repo,
        config,
        &["js", "ts"],
        r#"Route\.(get|post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]"#,
    )
}
