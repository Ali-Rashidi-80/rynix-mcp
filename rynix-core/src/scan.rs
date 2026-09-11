use std::path::Path;
use std::time::Instant;

use crate::frontend::extract_frontend_routes;
use crate::models::{ScanConfig, ScanResult, SCAN_SCHEMA};
use crate::rbac::build_rbac_matrix;
use crate::risk::scan_risk_surfaces;
use crate::routes::extract_api_routes;
use crate::secrets::scan_secrets;
use crate::stack_detect::detect_stacks;
use crate::taint::scan_taint;

pub fn analyze_repo(repo: &Path, config: ScanConfig, profile_hint: Option<String>) -> ScanResult {
    let started = Instant::now();
    let _stacks = if config.stack_hints.is_empty() {
        detect_stacks(repo)
    } else {
        config.stack_hints.clone()
    };
    let (routes, warnings) = extract_api_routes(repo, &config);
    let frontend_routes = extract_frontend_routes(repo, &config);
    let rbac_hints = build_rbac_matrix(&routes);
    let risk_surfaces = scan_risk_surfaces(&routes, &config);
    let secret_hits = scan_secrets(repo, &config);
    let taint_hints = scan_taint(repo, &config);

    let modules_scanned = routes
        .iter()
        .map(|r| r.file.clone())
        .collect::<std::collections::HashSet<_>>()
        .len();

    ScanResult {
        schema: SCAN_SCHEMA.to_string(),
        repo_path: repo.to_string_lossy().to_string(),
        profile_hint,
        modules_scanned,
        routes,
        frontend_routes,
        rbac_hints,
        risk_surfaces,
        secret_hits,
        taint_hints,
        warnings,
        duration_ms: started.elapsed().as_millis() as u64,
    }
}
