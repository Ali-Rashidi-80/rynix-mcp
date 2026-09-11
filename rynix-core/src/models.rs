use serde::{Deserialize, Serialize};

pub const SCAN_SCHEMA: &str = "rynix.scan.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretHit {
    pub file: String,
    pub line: u32,
    pub pattern: String,
    pub snippet: String,
    pub severity: String,
    pub rule_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintHint {
    pub file: String,
    pub line: u32,
    pub sink: String,
    pub snippet: String,
    pub severity: String,
    pub rule_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub schema: String,
    pub repo_path: String,
    pub profile_hint: Option<String>,
    pub modules_scanned: usize,
    pub routes: Vec<ApiRoute>,
    pub frontend_routes: Vec<FrontendRoute>,
    pub rbac_hints: Vec<RbacHint>,
    pub risk_surfaces: Vec<RiskSurface>,
    pub secret_hits: Vec<SecretHit>,
    pub taint_hints: Vec<TaintHint>,
    pub warnings: Vec<String>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiRoute {
    pub method: String,
    pub path: String,
    pub file: String,
    pub line: u32,
    pub handler: Option<String>,
    pub auth_required: bool,
    pub auth_hint: Option<String>,
    pub idor_risk_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrontendRoute {
    pub path: String,
    pub file: String,
    pub line: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbacHint {
    pub endpoint: String,
    pub file: String,
    pub line: u32,
    pub roles_detected: Vec<String>,
    pub abac_helpers: Vec<String>,
    pub idor_risk_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskSurface {
    pub path: String,
    pub method: String,
    pub file: String,
    pub line: u32,
    pub reason: String,
    pub severity: String,
    pub rule_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    #[serde(default)]
    pub api_roots: Vec<String>,
    #[serde(default = "default_frontend_root")]
    pub frontend_root: String,
    #[serde(default)]
    pub frontend_roots: Vec<String>,
    #[serde(default)]
    pub auth_markers: Vec<String>,
    #[serde(default)]
    pub risk_keywords_high: Vec<String>,
    #[serde(default)]
    pub risk_keywords_block: Vec<String>,
    #[serde(default)]
    pub stealth_public_prefixes: Vec<String>,
    #[serde(default)]
    pub stack_hints: Vec<String>,
}

fn default_frontend_root() -> String {
    "src".into()
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            api_roots: vec![
                "backend/app/api/v1/endpoints".into(),
                "app/api/v1/endpoints".into(),
                "app/api".into(),
            ],
            frontend_root: "src".into(),
            frontend_roots: vec!["src".into(), "frontend".into(), "apps/web".into()],
            auth_markers: vec![
                "get_current_user".into(),
                "get_current_active_user".into(),
                "require_roles".into(),
                "require_admin".into(),
                "check_case_access".into(),
                "get_current_active_superuser".into(),
            ],
            risk_keywords_high: vec![
                "purge".into(),
                "bulk-delete".into(),
                "bulk_delete".into(),
                "reverse".into(),
                "backup".into(),
                "password-reset".into(),
                "impersonate".into(),
            ],
            risk_keywords_block: vec!["sms".into(), "send-sms".into()],
            stealth_public_prefixes: vec![],
            stack_hints: vec![],
        }
    }
}

impl ScanConfig {
    #[allow(dead_code)]
    pub fn frontend_roots(&self) -> Vec<String> {
        if !self.frontend_roots.is_empty() {
            return self.frontend_roots.clone();
        }
        vec![self.frontend_root.clone()]
    }
}

/// Drop api_roots that are nested inside another root (deepest wins).
pub fn prune_nested_roots(roots: &[String]) -> Vec<String> {
    if roots.is_empty() {
        return Vec::new();
    }
    let normalized: Vec<(String, String)> = roots
        .iter()
        .map(|r| {
            let norm = r.trim_end_matches(['/', '\\']).replace('\\', "/");
            (r.clone(), norm)
        })
        .collect();
    let mut kept: Vec<String> = Vec::new();
    let mut seen_norm: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (i, (original, norm)) in normalized.iter().enumerate() {
        let nested = normalized.iter().enumerate().any(|(j, (_, other))| {
            i != j && norm != other && norm.starts_with(&format!("{other}/"))
        });
        if !nested && seen_norm.insert(norm.clone()) {
            kept.push(original.clone());
        }
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prune_drops_nested_api_roots() {
        let roots = vec![
            "backend/app/api".into(),
            "backend/app/api/v1/endpoints".into(),
            "app/api".into(),
        ];
        let kept = prune_nested_roots(&roots);
        assert_eq!(
            kept,
            vec![
                String::from("backend/app/api"),
                String::from("app/api"),
            ]
        );
    }
}
