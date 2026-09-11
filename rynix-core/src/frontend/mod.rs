mod angular;
mod nextjs;
mod nuxt;
mod react;
mod sveltekit;
mod vue;

use std::path::{Path, PathBuf};

use crate::models::{FrontendRoute, ScanConfig};

pub fn extract_frontend_routes(repo: &Path, config: &ScanConfig) -> Vec<FrontendRoute> {
    let mut routes = Vec::new();
    let roots = effective_frontend_roots(config);
    for root_rel in roots {
        let root = repo.join(&root_rel);
        if !root.is_dir() {
            continue;
        }
        let stack = detect_frontend_stack(repo, &root);
        let extracted = match stack.as_str() {
            "nextjs" => nextjs::extract(repo, &root),
            "nuxt" => nuxt::extract(repo, &root),
            "vue" => vue::extract(repo, &root),
            "angular" => angular::extract(repo, &root),
            "sveltekit" => sveltekit::extract(repo, &root),
            _ => react::extract(repo, &root),
        };
        routes.extend(extracted);
    }

    routes.sort_by(|a, b| a.path.cmp(&b.path).then(a.file.cmp(&b.file)));
    routes.dedup_by(|a, b| a.path == b.path && a.file == b.file);
    routes
}

fn detect_frontend_stack(repo: &Path, root: &Path) -> String {
    if has_dir(root, "app") && has_glob(root, "page.tsx") {
        return "nextjs".into();
    }
    let rel = root.strip_prefix(repo).unwrap_or(root).to_string_lossy().replace('\\', "/");
    if rel.contains("app/") || has_file_named(root, "next.config") {
        return "nextjs".into();
    }
    if has_file_named(root, "nuxt.config") || has_dir(root, "pages") && has_file_ext(root, "vue") {
        return "nuxt".into();
    }
    if has_file_named(root, "svelte.config") || has_dir(root, "routes") && has_glob(root, "+page.svelte") {
        return "sveltekit".into();
    }
    if has_file_named(root, "angular.json") {
        return "angular".into();
    }
    if has_file_ext(root, "vue") || has_file_named(root, "vite.config") {
        let pkg = repo.join("package.json");
        if pkg.is_file() {
            let text = std::fs::read_to_string(pkg).unwrap_or_default();
            if text.contains("\"vue\"") {
                return "vue".into();
            }
        }
    }
    "react".into()
}

fn has_file_named(root: &Path, stem: &str) -> bool {
    walkdir::WalkDir::new(root)
        .max_depth(3)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .any(|e| {
            e.path()
                .file_stem()
                .is_some_and(|s| s.to_string_lossy().starts_with(stem))
        })
}

fn has_dir(root: &Path, name: &str) -> bool {
    walkdir::WalkDir::new(root)
        .max_depth(2)
        .into_iter()
        .filter_map(|e| e.ok())
        .any(|e| e.file_type().is_dir() && e.file_name() == name)
}

fn has_file_ext(root: &Path, ext: &str) -> bool {
    walkdir::WalkDir::new(root)
        .max_depth(4)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .any(|e| e.path().extension().is_some_and(|x| x == ext))
}

fn has_glob(root: &Path, suffix: &str) -> bool {
    walkdir::WalkDir::new(root)
        .max_depth(5)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .any(|e| e.path().to_string_lossy().ends_with(suffix))
}

#[allow(dead_code)]
pub fn frontend_root_paths(repo: &Path, config: &ScanConfig) -> Vec<PathBuf> {
    effective_frontend_roots(config)
        .iter()
        .map(|r| repo.join(r))
        .filter(|p| p.is_dir())
        .collect()
}

fn effective_frontend_roots(config: &ScanConfig) -> Vec<String> {
    if !config.frontend_roots.is_empty() {
        config.frontend_roots.clone()
    } else {
        vec![config.frontend_root.clone()]
    }
}
