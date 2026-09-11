use regex::Regex;
use std::path::Path;

use crate::models::ScanConfig;

use super::common::extract_regex_routes;

pub fn extract_phoenix_routes(repo: &Path, config: &ScanConfig) -> Vec<crate::models::ApiRoute> {
    let re = Regex::new(r#"(get|post|put|patch|delete)\s+"([^"]+)"#).unwrap();
    extract_regex_routes(repo, config, &["ex"], &re, "GET")
}
