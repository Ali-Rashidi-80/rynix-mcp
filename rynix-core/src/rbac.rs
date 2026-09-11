use regex::Regex;

use crate::models::{ApiRoute, RbacHint};

pub fn build_rbac_matrix(routes: &[ApiRoute]) -> Vec<RbacHint> {
    let role_span_re =
        Regex::new(r"require_roles\s*\(\s*\[([\s\S]*?)\]").expect("role span regex");
    let role_item_re = Regex::new(r#"UserRole\.(\w+)|"(\w+)""#).expect("role item regex");

    const ABAC_MARKERS: [&str; 3] = [
        "check_case_access",
        "require_case_access",
        "ownership_check",
    ];

    routes
        .iter()
        .filter(|r| r.auth_required || r.idor_risk_score >= 50)
        .map(|r| {
            let mut roles = Vec::new();
            let joined = r.auth_hint.as_deref().unwrap_or("");

            if let Some(cap) = role_span_re.captures(joined) {
                let inner = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                for m in role_item_re.captures_iter(inner) {
                    let role = m
                        .get(1)
                        .or_else(|| m.get(2))
                        .map(|x| x.as_str().to_string())
                        .unwrap_or_default();
                    if !role.is_empty() {
                        roles.push(role);
                    }
                }
            }
            roles.sort();
            roles.dedup();

            let abac: Vec<String> = ABAC_MARKERS
                .iter()
                .filter(|mk| joined.contains(*mk))
                .map(|m| m.to_string())
                .collect();

            RbacHint {
                endpoint: format!("{} {}", r.method, r.path),
                file: r.file.clone(),
                line: r.line,
                roles_detected: roles,
                abac_helpers: abac,
                idor_risk_score: r.idor_risk_score,
            }
        })
        .collect()
}
