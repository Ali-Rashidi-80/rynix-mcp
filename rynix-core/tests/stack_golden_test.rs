//! Golden stack extractor tests — one per stacks/manifest.toml cargo_test.

use std::fs;
use tempfile::tempdir;

use rynix_core::models::ScanConfig;
use rynix_core::scan::analyze_repo;

fn default_config() -> ScanConfig {
    ScanConfig::default()
}

#[test]
fn flask_extracts_routes() {
    let dir = tempdir().unwrap();
    let app = dir.path().join("app.py");
    fs::write(
        app,
        r#"
from flask import Flask
app = Flask(__name__)

@app.route("/api/health", methods=["GET"])
def health():
    pass

@app.route("/api/users/<int:user_id>", methods=["POST"])
def user(user_id):
    pass
"#,
    )
    .unwrap();
    let mut config = default_config();
    config.stack_hints = vec!["flask".into()];
    let result = analyze_repo(dir.path(), config, None);
    assert!(result.routes.iter().any(|r| r.path.contains("health")));
}

#[test]
fn gin_extracts_routes() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("main.go"),
        r#"
package main
func main() {
    r := gin.Default()
    r.GET("/api/health", health)
    r.POST("/api/users/:id", updateUser)
}
"#,
    )
    .unwrap();
    let mut config = default_config();
    config.stack_hints = vec!["gin".into()];
    let result = analyze_repo(dir.path(), config, None);
    assert!(result.routes.iter().any(|r| r.path == "/api/health"));
}

#[test]
fn react_extracts_routes() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("App.tsx"),
        r#"
import { Route } from 'react-router-dom';
<Route path="/dashboard" element={<Dashboard />} />
<Route path="/cases" element={<Cases />} />
"#,
    )
    .unwrap();
    let result = analyze_repo(dir.path(), default_config(), None);
    assert!(result.frontend_routes.iter().any(|r| r.path == "/dashboard"));
}

#[test]
fn nextjs_extracts_routes() {
    let dir = tempdir().unwrap();
    let page = dir.path().join("app").join("dashboard").join("page.tsx");
    fs::create_dir_all(page.parent().unwrap()).unwrap();
    fs::write(page, "export default function Page() { return null }").unwrap();
    let mut config = default_config();
    config.frontend_root = ".".into();
    config.frontend_roots = vec![".".into()];
    let result = analyze_repo(dir.path(), config, None);
    assert!(
        result
            .frontend_routes
            .iter()
            .any(|r| r.path.contains("dashboard"))
    );
}

#[test]
fn vue_extracts_routes() {
    let dir = tempdir().unwrap();
    let router = dir.path().join("src").join("router.ts");
    fs::create_dir_all(router.parent().unwrap()).unwrap();
    fs::write(
        router,
        r#"
import { createRouter } from 'vue-router'
export default createRouter({ routes: [{ path: '/settings', component: Settings }] })
"#,
    )
    .unwrap();
    let result = analyze_repo(dir.path(), default_config(), None);
    assert!(result.frontend_routes.iter().any(|r| r.path == "/settings"));
}

#[test]
fn graphql_extracts_routes() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("schema.graphql"),
        r#"
type Query {
  users: [User]
  case(id: ID): Case
}
"#,
    )
    .unwrap();
    let mut config = default_config();
    config.stack_hints = vec!["graphql".into()];
    let result = analyze_repo(dir.path(), config, None);
    assert!(result.routes.iter().any(|r| r.path.contains("graphql")));
}

#[test]
fn trpc_extracts_routes() {
    let dir = tempdir().unwrap();
    let router = dir.path().join("src").join("router.ts");
    fs::create_dir_all(router.parent().unwrap()).unwrap();
    fs::write(
        router,
        r#"
import { createTRPCRouter, publicProcedure } from '@trpc/server'
export const appRouter = createTRPCRouter({
  listCases: publicProcedure.query(() => []),
})
"#,
    )
    .unwrap();
    let mut config = default_config();
    config.stack_hints = vec!["trpc".into()];
    let result = analyze_repo(dir.path(), config, None);
    assert!(result.routes.iter().any(|r| r.path.contains("listCases")));
}

#[test]
fn openapi_extracts_routes() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("openapi.json"),
        r#"{"paths":{"/api/v1/cases":{"get":{}},"/api/v1/clients/{id}":{"get":{}}}}"#,
    )
    .unwrap();
    let result = analyze_repo(dir.path(), default_config(), None);
    assert!(result.routes.iter().any(|r| r.path.contains("/api/v1/cases")));
}

#[test]
fn echo_extracts_routes() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("main.go"),
        r#"
e.GET("/api/health", health)
e.POST("/api/items/:id", update)
"#,
    )
    .unwrap();
    let mut config = default_config();
    config.stack_hints = vec!["echo".into()];
    let result = analyze_repo(dir.path(), config, None);
    assert!(result.routes.iter().any(|r| r.path == "/api/health"));
}

#[test]
fn axum_extracts_routes() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("main.rs"),
        r#"
.route("/api/health", get(health))
.route("/api/users/{id}", post(update_user))
"#,
    )
    .unwrap();
    let mut config = default_config();
    config.stack_hints = vec!["axum".into()];
    let result = analyze_repo(dir.path(), config, None);
    assert!(result.routes.iter().any(|r| r.path.contains("health")));
}

#[test]
fn actix_extracts_routes() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("main.rs"),
        r#"
web::get("/api/health").to(health)
web::post("/api/users/{id}").to(update)
"#,
    )
    .unwrap();
    let mut config = default_config();
    config.stack_hints = vec!["actix".into()];
    let result = analyze_repo(dir.path(), config, None);
    assert!(result.routes.iter().any(|r| r.path.contains("health")));
}

#[test]
fn koa_extracts_routes() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("app.js"),
        r#"router.get('/api/health', handler); router.post('/api/users/:id', handler);"#,
    )
    .unwrap();
    let mut config = default_config();
    config.stack_hints = vec!["koa".into()];
    let result = analyze_repo(dir.path(), config, None);
    assert!(result.routes.iter().any(|r| r.path == "/api/health"));
}

#[test]
fn hono_extracts_routes() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("index.ts"),
        r#"app.get('/api/health', (c) => c.json({}));"#,
    )
    .unwrap();
    let mut config = default_config();
    config.stack_hints = vec!["hono".into()];
    let result = analyze_repo(dir.path(), config, None);
    assert!(result.routes.iter().any(|r| r.path == "/api/health"));
}

#[test]
fn symfony_extracts_routes() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("Controller.php"),
        r#"#[Route('/api/health')] public function health() {}"#,
    )
    .unwrap();
    let mut config = default_config();
    config.stack_hints = vec!["symfony".into()];
    let result = analyze_repo(dir.path(), config, None);
    assert!(result.routes.iter().any(|r| r.path.contains("health")));
}

#[test]
fn sinatra_extracts_routes() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("app.rb"),
        r#"get '/api/health' do; end; post '/api/users/:id' do; end"#,
    )
    .unwrap();
    let mut config = default_config();
    config.stack_hints = vec!["sinatra".into()];
    let result = analyze_repo(dir.path(), config, None);
    assert!(result.routes.iter().any(|r| r.path == "/api/health"));
}

#[test]
fn phoenix_extracts_routes() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("router.ex"),
        r#"get "/api/health", HealthController, :index"#,
    )
    .unwrap();
    let mut config = default_config();
    config.stack_hints = vec!["phoenix".into()];
    let result = analyze_repo(dir.path(), config, None);
    assert!(result.routes.iter().any(|r| r.path.contains("health")));
}

#[test]
fn generic_extracts_routes() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("server.js"),
        r#"app.get('/api/health', () => {});"#,
    )
    .unwrap();
    let mut config = default_config();
    config.stack_hints = vec!["unknown-stack".into()];
    let result = analyze_repo(dir.path(), config, None);
    assert!(!result.routes.is_empty());
    assert!(
        result
            .warnings
            .iter()
            .any(|w| w.contains("generic_extractor_used"))
    );
}
