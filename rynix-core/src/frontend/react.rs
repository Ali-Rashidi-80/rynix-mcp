use regex::Regex;
use std::path::Path;

use crate::models::FrontendRoute;

pub fn extract(repo: &Path, root: &Path) -> Vec<FrontendRoute> {
    let mut routes = Vec::new();
    if !root.is_dir() {
        return routes;
    }

    let path_re = Regex::new(r#"path:\s*["'`]([^"'`]+)["'`]"#).expect("path re");
    let route_re = Regex::new(r#"<Route\s+[^>]*path=["']([^"']+)["']"#).expect("route re");
    let create_route_re =
        Regex::new(r#"createBrowserRouter\s*\(\s*\[([\s\S]*?)\]\s*\)"#).expect("browser router");

    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|x| x == "tsx" || x == "ts" || x == "jsx" || x == "js")
        })
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

        for (idx, line) in content.lines().enumerate() {
            let line_no = (idx + 1) as u32;
            for cap in path_re.captures_iter(line) {
                if let Some(p) = cap.get(1) {
                    routes.push(FrontendRoute {
                        path: p.as_str().to_string(),
                        file: rel.clone(),
                        line: line_no,
                    });
                }
            }
            for cap in route_re.captures_iter(line) {
                if let Some(p) = cap.get(1) {
                    routes.push(FrontendRoute {
                        path: p.as_str().to_string(),
                        file: rel.clone(),
                        line: line_no,
                    });
                }
            }
        }

        for cap in create_route_re.captures_iter(&content) {
            if let Some(block) = cap.get(1) {
                let block_start = cap.get(0).map(|m| m.start()).unwrap_or(0);
                let line_base = content[..block_start].lines().count() as u32;
                for pcap in path_re.captures_iter(block.as_str()) {
                    if let Some(p) = pcap.get(1) {
                        let rel_offset = pcap.get(0).map(|m| m.start()).unwrap_or(0);
                        let line_in_block = block.as_str()[..rel_offset].lines().count() as u32;
                        routes.push(FrontendRoute {
                            path: p.as_str().to_string(),
                            file: rel.clone(),
                            line: line_base + line_in_block + 1,
                        });
                    }
                }
            }
        }
    }
    routes
}
