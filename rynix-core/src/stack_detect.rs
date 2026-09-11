use std::path::{Path, PathBuf};

/// Lightweight stack detection from repository manifests (mirrors stack_detect.py).
pub fn detect_stacks(repo: &Path) -> Vec<String> {
    let mut stacks: Vec<String> = Vec::new();

    let pkg = repo.join("package.json");
    if pkg.is_file() {
        if let Ok(text) = std::fs::read_to_string(&pkg) {
            if text.contains("\"next\"") {
                stacks.push("nextjs".into());
            } else if text.contains("\"react\"") {
                stacks.push("react".into());
            }
            if text.contains("@nestjs/core") {
                stacks.push("nestjs".into());
            }
            if text.contains("\"express\"") {
                stacks.push("express".into());
            }
            if text.contains("\"fastify\"") {
                stacks.push("fastify".into());
            }
            if text.contains("\"vue\"") {
                stacks.push("vue".into());
            }
            if text.contains("\"nuxt\"") || text.contains("\"nuxt3\"") {
                stacks.push("nuxt".into());
            }
            if text.contains("@angular/core") {
                stacks.push("angular".into());
            }
            if text.contains("@sveltejs/kit") {
                stacks.push("sveltekit".into());
            }
            if text.contains("@trpc/server") {
                stacks.push("trpc".into());
            }
            if text.contains("graphql") {
                stacks.push("graphql".into());
            }
            if text.contains("\"koa\"") {
                stacks.push("koa".into());
            }
            if text.contains("hono") {
                stacks.push("hono".into());
            }
            if text.contains("@adonisjs/core") {
                stacks.push("adonisjs".into());
            }
        }
    }

    let go_mod = repo.join("go.mod");
    if go_mod.is_file() {
        if let Ok(text) = std::fs::read_to_string(&go_mod) {
            if text.contains("gin-gonic/gin") {
                stacks.push("gin".into());
            } else if text.contains("labstack/echo") {
                stacks.push("echo".into());
            } else if text.contains("gofiber/fiber") {
                stacks.push("fiber".into());
            } else if text.contains("go-chi/chi") {
                stacks.push("chi".into());
            }
        }
    }

    let pyproject = repo.join("pyproject.toml");
    let requirements = repo.join("requirements.txt");
    let mut py_text = String::new();
    if pyproject.is_file() {
        if let Ok(t) = std::fs::read_to_string(&pyproject) {
            py_text.push_str(&t);
        }
    }
    if requirements.is_file() {
        if let Ok(t) = std::fs::read_to_string(&requirements) {
            py_text.push_str(&t);
        }
    }
    let py_lower = py_text.to_lowercase();
    if py_lower.contains("fastapi") {
        stacks.push("fastapi".into());
    }
    if py_lower.contains("django") {
        stacks.push("django".into());
    }
    if py_lower.contains("flask") {
        stacks.push("flask".into());
    }

    let composer = repo.join("composer.json");
    if composer.is_file() {
        if let Ok(text) = std::fs::read_to_string(&composer) {
            if text.contains("laravel/framework") {
                stacks.push("laravel".into());
            }
            if text.contains("symfony/framework-bundle") {
                stacks.push("symfony".into());
            }
        }
    }

    let gemfile = repo.join("Gemfile");
    if gemfile.is_file() {
        if let Ok(text) = std::fs::read_to_string(&gemfile) {
            if text.contains("rails") {
                stacks.push("rails".into());
            }
            if text.contains("sinatra") {
                stacks.push("sinatra".into());
            }
        }
    }

    if repo.join("pom.xml").is_file() || !glob_paths(repo, "**/build.gradle*").is_empty() {
        stacks.push("spring".into());
    }

    if !glob_paths(repo, "**/*.csproj").is_empty() {
        stacks.push("aspnet".into());
    }

    let cargo = repo.join("Cargo.toml");
    if cargo.is_file() {
        if let Ok(text) = std::fs::read_to_string(&cargo) {
            if text.contains("axum") {
                stacks.push("axum".into());
            }
            if text.contains("actix-web") {
                stacks.push("actix".into());
            }
        }
    }

    if repo.join("mix.exs").is_file() {
        stacks.push("phoenix".into());
    }

    if repo.join("openapi.yaml").is_file()
        || repo.join("openapi.json").is_file()
        || repo.join("swagger.json").is_file()
    {
        stacks.push("openapi".into());
    }

    stacks.sort();
    stacks.dedup();
    stacks
}

fn glob_paths(repo: &Path, _pattern: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if _pattern.contains("csproj") {
        for entry in walkdir::WalkDir::new(repo)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            if entry.path().extension().is_some_and(|x| x == "csproj") {
                out.push(entry.path().to_path_buf());
            }
        }
    }
    if _pattern.contains("gradle") {
        for entry in walkdir::WalkDir::new(repo)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let name = entry.file_name().to_string_lossy();
            if name.starts_with("build.gradle") {
                out.push(entry.path().to_path_buf());
            }
        }
    }
    out
}
