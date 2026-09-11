use std::path::Path;

use regex::Regex;
use walkdir::WalkDir;

use crate::models::{ScanConfig, SecretHit};

const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "__tests__",
    ".pytest_cache",
    "dist",
    "build",
    "target",
    ".next",
    "backups",
    "tests",
    "test",
    "fixtures",
    "vendor",
];

const SCAN_EXTENSIONS: &[&str] = &[".py", ".ts", ".tsx", ".js", ".jsx", ".env", ".yaml", ".yml", ".toml", ".json"];

struct Pattern {
    id: &'static str,
    re: &'static str,
    severity: &'static str,
}

struct CompiledPattern {
    id: &'static str,
    severity: &'static str,
    re: Regex,
}

const PATTERNS: &[Pattern] = &[
    Pattern {
        id: "aws-access-key",
        re: r"AKIA[0-9A-Z]{16}",
        severity: "critical",
    },
    Pattern {
        id: "private-key-block",
        re: r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----",
        severity: "critical",
    },
    Pattern {
        id: "github-pat",
        re: r"ghp_[A-Za-z0-9]{20,}",
        severity: "high",
    },
    Pattern {
        id: "stripe-live",
        re: r"sk_live_[A-Za-z0-9]{16,}",
        severity: "critical",
    },
    Pattern {
        id: "jwt-secret-assignment",
        re: "(?i)(?:secret|jwt_secret|signing_key)\\s*[=:]\\s*[\"'][^\"']{12,}[\"']",
        severity: "high",
    },
];

fn should_skip(path: &Path) -> bool {
    path.components().any(|c| {
        let s = c.as_os_str().to_string_lossy();
        SKIP_DIRS.iter().any(|skip| s == *skip)
    })
}

fn is_env_file(name: &str) -> bool {
    name == ".env" || name.starts_with(".env.") || name.ends_with(".env")
}

fn ext_allowed(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if is_env_file(name) {
        return true;
    }
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| SCAN_EXTENSIONS.iter().any(|ext| ext.strip_prefix('.') == Some(e)))
        .unwrap_or(false)
}

pub fn scan_secrets(repo: &Path, _config: &ScanConfig) -> Vec<SecretHit> {
    let mut hits = Vec::new();
    let compiled: Vec<CompiledPattern> = PATTERNS
        .iter()
        .filter_map(|p| {
            Regex::new(p.re).ok().map(|re| CompiledPattern {
                id: p.id,
                severity: p.severity,
                re,
            })
        })
        .collect();

    // R-44: always scan full repo; api_roots only steer other analyzers.
    let scan_roots: Vec<&Path> = vec![repo.as_ref()];

    for root in scan_roots {
        for entry in WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if !path.is_file() || should_skip(path) || !ext_allowed(path) {
                continue;
            }
            let meta = match std::fs::metadata(path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.len() > 512_000 {
                continue;
            }
            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            for pat in &compiled {
                for (idx, line) in content.lines().enumerate() {
                    if pat.re.is_match(line) {
                        let rel = path
                            .strip_prefix(repo)
                            .unwrap_or(path)
                            .to_string_lossy()
                            .replace('\\', "/");
                        hits.push(SecretHit {
                            file: rel,
                            line: (idx + 1) as u32,
                            pattern: pat.id.into(),
                            snippet: redact_line(line),
                            severity: pat.severity.into(),
                            rule_id: "RYNIX-STATIC-SECRET".into(),
                        });
                        break;
                    }
                }
            }
        }
    }

    hits
}

fn redact_line(line: &str) -> String {
    let t = line.trim();
    // LHS must look like KEY (optionally "export KEY") before '='
    let eq_valid = t.find('=').and_then(|pos| {
        let lhs = t[..pos].trim_start();
        let lhs = lhs.strip_prefix("export ").unwrap_or(lhs).trim_end();
        let ok = !lhs.is_empty()
            && lhs.len() <= 64
            && lhs.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        ok.then_some(pos)
    });
    let colon_valid = t.find(':').and_then(|idx| {
        (idx > 0 && t[..idx].chars().all(|c| c.is_ascii_alphabetic() || c == '_')).then_some(idx)
    });

    if let Some(pos) = eq_valid.or(colon_valid) {
        let prefix = &t[..pos + 1];
        let value = t[pos + 1..].trim_start();
        let head: String = value.chars().take(6).collect();
        return format!("{prefix}{head}…[REDACTED]");
    }
    // no trustworthy separator: mask everything except a tiny head
    let char_count = t.chars().count();
    let head: String = t.chars().take(6).collect();
    let tail = if char_count > 12 {
        "…[REDACTED]"
    } else {
        "[REDACTED]"
    };
    format!("{head}{tail}")
}
