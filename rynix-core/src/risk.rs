use crate::models::{ApiRoute, RiskSurface, ScanConfig};

fn path_has_keyword(path: &str, kw: &str) -> bool {
    let kw = kw.to_lowercase();
    path.to_lowercase()
        .split('/')
        .filter(|seg| !seg.is_empty())
        .any(|seg| seg == kw || seg.contains(&kw))
}

fn file_in_finance_module(file: &str) -> bool {
    let normalized = file.replace('\\', "/").to_lowercase();
    normalized.contains("/finance/") || normalized.ends_with("/finance")
}

pub fn scan_risk_surfaces(routes: &[ApiRoute], config: &ScanConfig) -> Vec<RiskSurface> {
    let mut surfaces = Vec::new();

    for route in routes {
        let path_lower = route.path.to_lowercase();

        for kw in &config.risk_keywords_high {
            if path_has_keyword(&path_lower, kw) {
                surfaces.push(RiskSurface {
                    path: route.path.clone(),
                    method: route.method.clone(),
                    file: route.file.clone(),
                    line: route.line,
                    reason: format!("high-risk keyword: {}", kw),
                    severity: if kw.contains("purge") || kw.contains("impersonate") {
                        "critical".into()
                    } else {
                        "high".into()
                    },
                    rule_id: "RYNIX-STATIC-RISK".into(),
                });
                break;
            }
        }

        for kw in &config.risk_keywords_block {
            if path_has_keyword(&path_lower, kw) {
                surfaces.push(RiskSurface {
                    path: route.path.clone(),
                    method: route.method.clone(),
                    file: route.file.clone(),
                    line: route.line,
                    reason: format!("blocked surface unless allow_sms: {}", kw),
                    severity: "high".into(),
                    rule_id: "RYNIX-STATIC-RISK".into(),
                });
            }
        }

        if route.idor_risk_score >= 80 {
            surfaces.push(RiskSurface {
                path: route.path.clone(),
                method: route.method.clone(),
                file: route.file.clone(),
                line: route.line,
                reason: "path parameter without strong auth/ABAC markers".into(),
                severity: "high".into(),
                rule_id: "RYNIX-API1-IDOR".into(),
            });
        }

        for prefix in &config.stealth_public_prefixes {
            if route.path.starts_with(prefix) && !route.auth_required {
                surfaces.push(RiskSurface {
                    path: route.path.clone(),
                    method: route.method.clone(),
                    file: route.file.clone(),
                    line: route.line,
                    reason: format!(
                        "stealth public prefix {} but no auth markers on handler",
                        prefix
                    ),
                    severity: "medium".into(),
                    rule_id: "RYNIX-STEALTH-BYPASS".into(),
                });
            }
        }

        if route.method == "DELETE" && file_in_finance_module(&route.file) {
            surfaces.push(RiskSurface {
                path: route.path.clone(),
                method: route.method.clone(),
                file: route.file.clone(),
                line: route.line,
                reason: "DELETE on finance module — expect POST-only purge".into(),
                severity: "critical".into(),
                rule_id: "RYNIX-STATIC-RISK".into(),
            });
        }
    }

    surfaces
}
