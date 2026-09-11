use regex::Regex;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::models::{ApiRoute, ScanConfig};

pub fn merge_routes(into: &mut Vec<ApiRoute>, from: Vec<ApiRoute>) {
    let mut seen: HashSet<(String, String, String)> = into
        .iter()
        .map(|r| (r.method.clone(), r.path.clone(), r.file.clone()))
        .collect();
    for r in from {
        let key = (r.method.clone(), r.path.clone(), r.file.clone());
        if seen.insert(key) {
            into.push(r);
        }
    }
}

pub fn source_roots(repo: &Path, config: &ScanConfig) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = config
        .api_roots
        .iter()
        .map(|r| repo.join(r))
        .filter(|p| p.is_dir())
        .collect();
    if roots.is_empty() {
        roots.push(repo.to_path_buf());
    }
    roots
}

pub fn should_skip_dir(name: &str) -> bool {
    matches!(
        name,
        "node_modules" | ".git" | "dist" | "build" | "target" | ".venv" | "__pycache__"
    )
}

pub fn walk_files(repo: &Path, roots: &[PathBuf], extensions: &[&str]) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    for root in roots {
        for entry in walkdir::WalkDir::new(root)
            .into_iter()
            .filter_entry(|e| {
                if e.file_type().is_file() {
                    return true;
                }
                e.depth() == 0 || !should_skip_dir(e.file_name().to_string_lossy().as_ref())
            })
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !extensions.contains(&ext) {
                continue;
            }
            let rel = path
                .strip_prefix(repo)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            if std::fs::read_to_string(path).is_ok() {
                out.push((path.to_path_buf(), rel));
            }
        }
    }
    out
}

pub fn auth_from_line(line: &str, markers: &[String]) -> (bool, Option<String>) {
    static AUTH_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let auth_re = AUTH_RE.get_or_init(|| {
        Regex::new(r"(?i)(?:useguards|jwtauthguard|require_?auth|auth_required|permission_classes|login_required|authenticat(?:ed?|ion)|authorized?|protected|permission|guard|\bauth\b)").unwrap()
    });
    let lower = line.to_lowercase();
    let auth = auth_re.is_match(line)
        || lower.contains("body(")
        || markers.iter().any(|m| line.contains(m.as_str()));
    let hint = markers.iter().find(|m| line.contains(m.as_str())).map(|s| s.clone());
    (auth, hint)
}

pub fn extract_regex_routes(
    repo: &Path,
    config: &ScanConfig,
    extensions: &[&str],
    re: &Regex,
    default_method: &str,
) -> Vec<ApiRoute> {
    let roots = source_roots(repo, config);
    let files = walk_files(repo, &roots, extensions);
    let mut routes = Vec::new();
    for (_path, rel) in files {
        let content = std::fs::read_to_string(repo.join(&rel)).unwrap_or_default();
        push_regex_matches(&mut routes, &content, &rel, re, default_method, &config.auth_markers);
    }
    routes
}

pub fn idor_score(path: &str, auth_required: bool) -> u8 {
    let has_object_param = (path.contains('{') && path.contains('}'))
        || path.split('/').any(|seg| seg.starts_with(':') && seg.len() > 1)
        || path.contains("<int:")
        || path.contains("<uuid:")
        || path.contains("<str:");
    if !has_object_param {
        return 10;
    }
    if auth_required {
        55
    } else {
        90
    }
}

pub fn extract_http_method_routes(
    repo: &Path,
    config: &ScanConfig,
    extensions: &[&str],
    pattern: &str,
) -> Vec<ApiRoute> {
    let re = Regex::new(pattern).expect("route pattern");
    let roots = source_roots(repo, config);
    let files = walk_files(repo, &roots, extensions);
    let mut routes = Vec::new();
    for (_path, rel) in files {
        let content = std::fs::read_to_string(repo.join(&rel)).unwrap_or_default();
        push_regex_matches(&mut routes, &content, &rel, &re, "GET", &config.auth_markers);
    }
    routes
}

pub fn push_regex_matches(
    routes: &mut Vec<ApiRoute>,
    content: &str,
    rel: &str,
    re: &Regex,
    default_method: &str,
    markers: &[String],
) {
    for (idx, line) in content.lines().enumerate() {
        for cap in re.captures_iter(line) {
            let method = cap
                .get(1)
                .map(|m| m.as_str().to_uppercase())
                .filter(|m| !m.is_empty())
                .unwrap_or_else(|| default_method.to_string());
            let path = cap
                .get(2)
                .map(|m| m.as_str())
                .unwrap_or("/")
                .to_string();
            let (auth_required, auth_hint) = auth_from_line(line, markers);
            let idor = idor_score(&path, auth_required);
            routes.push(ApiRoute {
                method,
                path,
                file: rel.to_string(),
                line: (idx + 1) as u32,
                handler: None,
                auth_required,
                auth_hint,
                idor_risk_score: idor,
            });
        }
    }
}
