use regex::Regex;
use std::path::{Path, PathBuf};

use crate::models::{prune_nested_roots, ApiRoute, ScanConfig};

pub fn extract_fastapi_routes(repo: &Path, config: &ScanConfig) -> (Vec<ApiRoute>, Vec<String>) {
    let mut routes = Vec::new();
    let mut warnings = Vec::new();

    let decorator_re = Regex::new(
        r#"@(?:router|app)\.(get|post|put|patch|delete|head|options|api_route)\s*\(\s*["']([^"']+)["']"#,
    )
    .expect("decorator regex");
    let route_decorator_re =
        Regex::new(r#"@router\.route\s*\(\s*["']([^"']+)["']\s*,\s*methods\s*=\s*\[([^\]]+)\]"#)
            .expect("route decorator regex");
    let api_route_methods_re =
        Regex::new(r#"methods\s*=\s*\[([^\]]+)\]"#).expect("api_route methods regex");
    let handler_re = Regex::new(r"^(?:async\s+)?def\s+(\w+)").expect("handler regex");
    let depends_re = Regex::new(r"Depends\s*\(").expect("depends regex");

    let api_dirs: Vec<PathBuf> = prune_nested_roots(&config.api_roots)
        .iter()
        .map(|r| repo.join(r))
        .filter(|p| p.is_dir())
        .collect();

    if api_dirs.is_empty() {
        warnings.push("no_api_root_found: tried backend/app/api, app/api".into());
        return (routes, warnings);
    }

    for api_dir in api_dirs {
        for entry in walkdir::WalkDir::new(&api_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "py"))
        {
            let path = entry.path();
            let rel = path
                .strip_prefix(repo)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let lines: Vec<&str> = content.lines().collect();

            for (idx, line) in lines.iter().enumerate() {
                let line_no = (idx + 1) as u32;

                for cap in decorator_re.captures_iter(line) {
                    let raw_method = cap.get(1).map(|m| m.as_str().to_uppercase()).unwrap_or_default();
                    let route_path = cap.get(2).map(|m| m.as_str()).unwrap_or("/").to_string();
                    let handler = find_handler_name(&lines, idx, &handler_re);
                    let auth = detect_auth(&lines, idx, &depends_re, &config.auth_markers);
                    let idor = score_idor(&route_path, auth.auth_required, &auth.abac_markers);

                    if raw_method == "API_ROUTE" {
                        let methods = api_route_methods_re
                            .captures(line)
                            .map(|c| parse_methods(c.get(1).map(|m| m.as_str()).unwrap_or("GET")))
                            .filter(|m| !m.is_empty())
                            .unwrap_or_else(|| vec!["GET".to_string()]);
                        for method in methods {
                            routes.push(ApiRoute {
                                method,
                                path: route_path.clone(),
                                file: rel.clone(),
                                line: line_no,
                                handler: handler.clone(),
                                auth_required: auth.auth_required,
                                auth_hint: auth.hint.clone(),
                                idor_risk_score: idor,
                            });
                        }
                        continue;
                    }

                    routes.push(ApiRoute {
                        method: raw_method,
                        path: route_path,
                        file: rel.clone(),
                        line: line_no,
                        handler,
                        auth_required: auth.auth_required,
                        auth_hint: auth.hint,
                        idor_risk_score: idor,
                    });
                }

                if let Some(cap) = route_decorator_re.captures(line) {
                    let route_path = cap.get(1).map(|m| m.as_str()).unwrap_or("/").to_string();
                    let methods_str = cap.get(2).map(|m| m.as_str()).unwrap_or("GET");
                    for method in parse_methods(methods_str) {
                        let auth = detect_auth(&lines, idx, &depends_re, &config.auth_markers);
                        let idor = score_idor(&route_path, auth.auth_required, &auth.abac_markers);
                        routes.push(ApiRoute {
                            method,
                            path: route_path.clone(),
                            file: rel.clone(),
                            line: line_no,
                            handler: find_handler_name(&lines, idx, &handler_re),
                            auth_required: auth.auth_required,
                            auth_hint: auth.hint,
                            idor_risk_score: idor,
                        });
                    }
                }
            }
        }
    }

    (routes, warnings)
}

struct AuthDetect {
    auth_required: bool,
    hint: Option<String>,
    abac_markers: Vec<String>,
}

fn detect_auth(
    lines: &[&str],
    decorator_idx: usize,
    depends_re: &Regex,
    markers: &[String],
) -> AuthDetect {
    let window_end = (decorator_idx + 25).min(lines.len());
    let mut auth_required = false;
    let mut hint = None;
    let mut abac_markers = Vec::new();
    let base_indent = lines
        .get(decorator_idx)
        .map(|l| l.chars().take_while(|c| c.is_whitespace()).count())
        .unwrap_or(0);
    let mut joined = String::new();

    for line in lines.iter().take(window_end).skip(decorator_idx) {
        let trimmed = line.trim_start();
        let line_indent = line.chars().take_while(|c| c.is_whitespace()).count();
        let is_handler_def = trimmed.starts_with("def ") || trimmed.starts_with("async def ");
        if !joined.is_empty() {
            if trimmed.starts_with('@') {
                break;
            }
            if is_handler_def && line_indent <= base_indent {
                joined.push_str(line);
                joined.push('\n');
                if line.contains("Body(") && (line.contains("Depends") || line.contains("Security")) {
                    auth_required = true;
                }
                if depends_re.is_match(line) {
                    auth_required = true;
                }
                if line.contains("current_user:")
                    && (line.contains("CurrentActiveUser")
                        || line.contains("CeoRead")
                        || line.contains("CeoWrite")
                        || line.contains("CeoApprove")
                        || line.contains("FinanceUser")
                        || line.contains("FinanceProfileReader"))
                {
                    auth_required = true;
                }
                for marker in markers {
                    if line.contains(marker) {
                        auth_required = true;
                        if marker.contains("case_access") {
                            abac_markers.push(marker.clone());
                        }
                        if hint.is_none() {
                            hint = Some(marker.clone());
                        }
                    }
                }
                if line.contains('(') && !line.contains(')') {
                    continue;
                }
                break;
            }
        }
        joined.push_str(line);
        joined.push('\n');

        if line.contains("Body(") && (line.contains("Depends") || line.contains("Security")) {
            auth_required = true;
        }
        if depends_re.is_match(line) {
            auth_required = true;
        }
        if line.contains("current_user:")
            && (line.contains("CurrentActiveUser")
                || line.contains("CeoRead")
                || line.contains("CeoWrite")
                || line.contains("CeoApprove")
                || line.contains("FinanceUser")
                || line.contains("FinanceProfileReader"))
        {
            auth_required = true;
        }
        for marker in markers {
            if line.contains(marker) {
                auth_required = true;
                if marker.contains("case_access") {
                    abac_markers.push(marker.clone());
                }
                if hint.is_none() {
                    hint = Some(marker.clone());
                }
            }
        }
    }

    if auth_required && hint.is_none() {
        hint = Some(truncate_line(&joined));
    }

    AuthDetect {
        auth_required,
        hint,
        abac_markers,
    }
}

fn find_handler_name(lines: &[&str], decorator_idx: usize, handler_re: &Regex) -> Option<String> {
    for line in lines.iter().skip(decorator_idx).take(8) {
        if let Some(cap) = handler_re.captures(line) {
            return cap.get(1).map(|m| m.as_str().to_string());
        }
    }
    None
}

fn parse_methods(methods_str: &str) -> Vec<String> {
    methods_str
        .split(',')
        .filter_map(|m| {
            let m = m.trim().trim_matches('"').trim_matches('\'').to_uppercase();
            if m.is_empty() {
                None
            } else {
                Some(m)
            }
        })
        .collect()
}

fn score_idor(path: &str, auth_required: bool, abac: &[String]) -> u8 {
    let has_id = path.contains('{') && path.contains('}');
    if !has_id {
        return 10;
    }
    if !abac.is_empty() {
        return 25;
    }
    if auth_required {
        return 55;
    }
    90
}

fn truncate_line(line: &str) -> String {
    let t = line.trim();
    if t.chars().count() <= 117 {
        return t.to_string();
    }
    let cut: String = t.chars().take(114).collect();
    format!("{cut}...")
}
