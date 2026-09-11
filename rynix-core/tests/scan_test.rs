use std::fs;
use tempfile::tempdir;

use rynix_core::models::ScanConfig;
use rynix_core::scan::analyze_repo;

#[test]
fn extracts_fastapi_routes_from_fixture() {
    let dir = tempdir().unwrap();
    let endpoints = dir.path().join("backend/app/api/v1/endpoints");
    fs::create_dir_all(&endpoints).unwrap();
    fs::write(
        endpoints.join("cases.py"),
        r#"
from fastapi import APIRouter, Depends
router = APIRouter()

@router.get("/items/{item_id}")
async def get_item(item_id: int, current_user: CurrentActiveUser):
    pass

@router.post("/finance/case-fee-receipts/{event_id}/purge")
async def purge_receipt(event_id: str, user=Depends(require_roles([UserRole.CEO]))):
    pass
"#,
    )
    .unwrap();

    let mut config = ScanConfig::default();
    config.auth_markers.push("get_current_user".into());
    let result = analyze_repo(dir.path(), config, None);
    assert!(result.routes.len() >= 2);
    assert!(result.risk_surfaces.iter().any(|s| s.path.contains("purge")));
}

#[test]
fn detects_hardcoded_secret_patterns() {
    let dir = tempdir().unwrap();
    let endpoints = dir.path().join("backend/app/api/v1/endpoints");
    fs::create_dir_all(&endpoints).unwrap();
    fs::write(
        endpoints.join("config_leak.py"),
        "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n",
    )
    .unwrap();

    let config = ScanConfig::default();
    let result = analyze_repo(dir.path(), config, None);
    assert!(result.secret_hits.iter().any(|h| h.pattern == "aws-access-key"));
}

#[test]
fn taint_ignores_literal_sink_args() {
    let dir = tempdir().unwrap();
    let endpoints = dir.path().join("backend/app/api/v1/endpoints");
    fs::create_dir_all(&endpoints).unwrap();
    fs::write(
        endpoints.join("safe.py"),
        "def ok():\n    eval(\"1+1\")\n",
    )
    .unwrap();
    fs::write(
        endpoints.join("unsafe.py"),
        "def bad(user_input):\n    eval(user_input)\n",
    )
    .unwrap();

    let config = ScanConfig::default();
    let result = analyze_repo(dir.path(), config, None);
    assert!(
        result.taint_hints.iter().any(|h| h.file.ends_with("/unsafe.py")),
        "dynamic eval should be flagged"
    );
    assert!(
        !result.taint_hints.iter().any(|h| h.file.ends_with("/safe.py")),
        "literal eval should not be flagged: {:?}",
        result.taint_hints
    );
}

#[test]
fn secret_snippets_are_redacted() {
    let dir = tempdir().unwrap();
    let endpoints = dir.path().join("backend/app/api/v1/endpoints");
    fs::create_dir_all(&endpoints).unwrap();
    let secret = "sk_live_51H8xYzABCDEFGHIJKLMNOP";
    fs::write(
        endpoints.join("leak.py"),
        format!("STRIPE_KEY = \"{secret}\"\n"),
    )
    .unwrap();

    let config = ScanConfig::default();
    let result = analyze_repo(dir.path(), config, None);
    let hit = result
        .secret_hits
        .iter()
        .find(|h| h.pattern == "stripe-live")
        .expect("stripe pattern");
    assert!(!hit.snippet.contains(secret));
    assert!(hit.snippet.contains("[REDACTED]"));
}

#[test]
fn frontend_router_reports_real_line_numbers() {
    let dir = tempdir().unwrap();
    let frontend = dir.path().join("src");
    fs::create_dir_all(&frontend).unwrap();
    fs::write(
        frontend.join("App.tsx"),
        r#"
import { createBrowserRouter } from 'react-router-dom';

const router = createBrowserRouter([
  { path: '/dashboard', element: <Dashboard /> },
  { path: '/cases', element: <Cases /> },
]);
"#,
    )
    .unwrap();

    let config = ScanConfig::default();
    let result = analyze_repo(dir.path(), config, None);
    let dashboard = result
        .frontend_routes
        .iter()
        .find(|r| r.path == "/dashboard")
        .expect("dashboard route");
    assert!(dashboard.line > 1, "line should not be hardcoded to 1");
}

#[test]
fn risk_keywords_ignore_file_path_substrings() {
    let dir = tempdir().unwrap();
    let endpoints = dir.path().join("backend/app/api/v1/endpoints");
    fs::create_dir_all(&endpoints).unwrap();
    fs::write(
        endpoints.join("assumptions.py"),
        r#"
from fastapi import APIRouter
router = APIRouter()

@router.get("/items/{item_id}")
async def get_item(item_id: int):
    pass
"#,
    )
    .unwrap();

    let config = ScanConfig::default();
    let result = analyze_repo(dir.path(), config, None);
    assert!(
        !result
            .risk_surfaces
            .iter()
            .any(|s| s.path == "/items/{item_id}" && s.reason.contains("sms")),
        "file path substring must not trigger block keyword"
    );
}

#[test]
fn secrets_scan_skips_test_directories() {
    let dir = tempdir().unwrap();
    let tests = dir.path().join("backend/tests");
    fs::create_dir_all(&tests).unwrap();
    fs::write(
        tests.join("fixtures.py"),
        "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n",
    )
    .unwrap();

    let config = ScanConfig::default();
    let result = analyze_repo(dir.path(), config, None);
    assert!(
        result.secret_hits.is_empty(),
        "test/fixture trees should be skipped: {:?}",
        result.secret_hits
    );
}

#[test]
fn django_extracts_routes() {
    let dir = tempdir().unwrap();
    let urls = dir.path().join("backend/app/api");
    fs::create_dir_all(&urls).unwrap();
    fs::write(
        urls.join("urls.py"),
        r#"
from django.urls import path
from . import views
urlpatterns = [
    path('users/', views.list_users),
    path('users/<int:pk>/', views.detail),
]
"#,
    )
    .unwrap();
    let config = ScanConfig::default();
    let result = analyze_repo(dir.path(), config, None);
    assert!(result.routes.iter().any(|r| r.path.contains("users")));
}

#[test]
fn express_extracts_routes() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("app.js"),
        r#"
const express = require('express');
const app = express();
app.get('/api/health', (req, res) => res.send('ok'));
app.post('/api/users/:id', (req, res) => res.json({}));
"#,
    )
    .unwrap();
    let config = ScanConfig::default();
    let result = analyze_repo(dir.path(), config, None);
    assert!(result.routes.iter().any(|r| r.path == "/api/health"));
    assert!(result.routes.iter().any(|r| r.method == "POST"));
}

#[test]
fn nestjs_extracts_routes() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("users.controller.ts"),
        r#"
@Controller('users')
export class UsersController {
  @Get(':id')
  findOne() {}
  @Post()
  create() {}
}
"#,
    )
    .unwrap();
    let config = ScanConfig::default();
    let result = analyze_repo(dir.path(), config, None);
    assert!(result.routes.iter().any(|r| r.method == "GET" || r.method == "POST"));
}

#[test]
fn echo_extracts_routes() {
    let dir = tempdir().unwrap();
    let main_go = dir.path().join("main.go");
    std::fs::write(
        main_go,
        r#"
package main
import "github.com/labstack/echo/v4"
func main() {
    e := echo.New()
    e.GET("/api/health", nil)
    e.POST("/api/users/:id", nil)
}
"#,
    )
    .unwrap();
    let config = ScanConfig::default();
    let result = analyze_repo(dir.path(), config, None);
    assert!(result.routes.iter().any(|r| r.path.contains("health")));
}

#[test]
fn axum_extracts_routes() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("main.rs"),
        r#"
use axum::Router;
fn app() -> Router {
    Router::new().route("/api/health", axum::routing::get(|| async {}))
}
"#,
    )
    .unwrap();
    let config = ScanConfig::default();
    let result = analyze_repo(dir.path(), config, None);
    assert!(result.routes.iter().any(|r| r.path.contains("health")));
}

#[test]
fn react_extracts_routes() {
    let dir = tempdir().unwrap();
    let frontend = dir.path().join("src");
    std::fs::create_dir_all(&frontend).unwrap();
    std::fs::write(
        frontend.join("App.tsx"),
        r#"<Route path="/dashboard" element={<Dashboard />} />"#,
    )
    .unwrap();
    let config = ScanConfig::default();
    let result = analyze_repo(dir.path(), config, None);
    assert!(result.frontend_routes.iter().any(|r| r.path == "/dashboard"));
}

#[test]
fn graphql_extracts_routes() {
    let dir = tempdir().unwrap();
    let schema = dir.path().join("schema.graphql");
    std::fs::write(
        schema,
        r#"
type Query {
  users: [User]
  health: String
}
"#,
    )
    .unwrap();
    let config = ScanConfig::default();
    let result = analyze_repo(dir.path(), config, None);
    assert!(result.routes.iter().any(|r| r.path.contains("graphql")));
}

#[test]
fn generic_extracts_routes() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("app.js"),
        r#"app.get('/api/health', (req, res) => res.send('ok'));"#,
    )
    .unwrap();
    let mut config = ScanConfig::default();
    config.stack_hints = vec!["unknown-stack".into()];
    let result = analyze_repo(dir.path(), config, None);
    assert!(
        result.warnings.iter().any(|w| w.contains("generic_extractor_used"))
            || result.routes.iter().any(|r| r.path.contains("health"))
    );
}

#[test]
fn secret_snippets_with_equals_sign_not_leaked() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    fs::create_dir_all(&src).unwrap();
    let pad_secret = "c2VjcmV0X2tleV9iYXNlNjRfZW5jb2RlZA==";
    fs::write(
        src.join(".env.prod"),
        format!("export JWT_SECRET=\"{pad_secret}\"\nexport DB_PASSWORD=\"my=secret=password==\"\n"),
    )
    .unwrap();

    let config = ScanConfig::default();
    let result = analyze_repo(dir.path(), config, None);
    for hit in &result.secret_hits {
        assert!(
            !hit.snippet.contains(pad_secret),
            "Secret with base64 padding should not be leaked verbatim in snippet: {}",
            hit.snippet
        );
        assert!(
            !hit.snippet.contains("my=secret=password=="),
            "Secret with multiple = signs should not leak in snippet: {}",
            hit.snippet
        );
        assert!(hit.snippet.contains("[REDACTED]"));
    }
}

#[test]
fn express_route_extractor_filters_middleware_and_config() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("routes.js"),
        r#"
const express = require('express');
const app = express();
app.use(express.json());
app.use('/static', express.static('public'));
app.get('env');
app.get('port');
app.get('/api/users', (req, res) => res.json([]));
app.post(`/api/items`, (req, res) => res.send('created'));
"#,
    )
    .unwrap();

    let mut config = ScanConfig::default();
    config.stack_hints = vec!["express".into()];
    let result = analyze_repo(dir.path(), config, None);
    let paths: Vec<&str> = result.routes.iter().map(|r| r.path.as_str()).collect();
    assert!(paths.contains(&"/api/users"), "Should extract /api/users");
    assert!(paths.contains(&"/api/items"), "Should extract backtick route /api/items");
    assert!(!paths.contains(&"env"), "app.get('env') config call must not be a route");
    assert!(!paths.contains(&"port"), "app.get('port') config call must not be a route");
    assert!(!result.routes.iter().any(|r| r.method == "USE"), "app.use must not be extracted as USE route");
}

#[test]
fn auth_compound_tokens_and_authors_distinction() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("app.js"),
        r#"
// Route 1: with auth guard
// @UseGuards(JwtAuthGuard)
app.get('/api/protected', (req, res) => res.json({}));

// Route 2: /api/authors (should not trigger false positive auth)
app.get('/api/authors', (req, res) => res.json([]));
"#,
    )
    .unwrap();

    let mut config = ScanConfig::default();
    config.stack_hints = vec!["express".into()];
    let result = analyze_repo(dir.path(), config, None);
    let protected = result.routes.iter().find(|r| r.path == "/api/protected");
    let authors = result.routes.iter().find(|r| r.path == "/api/authors");
    assert!(protected.is_some(), "Should find /api/protected");
    assert!(authors.is_some(), "Should find /api/authors");
    assert!(protected.unwrap().auth_required, "protected route with @UseGuards should be authed");
    assert!(!authors.unwrap().auth_required, "authors route without auth should not be authed");
}
