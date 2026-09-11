mod graphql;
mod openapi;
mod trpc;

use std::path::Path;

use crate::models::{ApiRoute, ScanConfig};

pub use graphql::extract_graphql_routes;
pub use openapi::extract_openapi_routes;
pub use trpc::extract_trpc_routes;

pub fn extract_api_style_routes(
    repo: &Path,
    config: &ScanConfig,
    stacks: &[String],
) -> (Vec<ApiRoute>, Vec<String>) {
    let mut routes = Vec::new();
    let mut warnings = Vec::new();

    let run = |name: &str| stacks.is_empty() || stacks.iter().any(|s| s == name);

    if run("graphql") {
        let graphql = extract_graphql_routes(repo, config);
        if !graphql.is_empty() {
            warnings.push("api_style:graphql_detected".into());
        }
        routes.extend(graphql);
    }
    if run("trpc") {
        let trpc = extract_trpc_routes(repo, config);
        if !trpc.is_empty() {
            warnings.push("api_style:trpc_detected".into());
        }
        routes.extend(trpc);
    }
    if run("openapi") || stacks.is_empty() {
        let openapi = extract_openapi_routes(repo, config);
        if !openapi.is_empty() {
            warnings.push("api_style:openapi_merged".into());
        }
        routes.extend(openapi);
    }

    (routes, warnings)
}
