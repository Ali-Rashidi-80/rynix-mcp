mod actix;
mod adonisjs;
mod aspnet;
mod axum;
mod chi;
pub mod common;
mod django;
mod echo;
mod express;
mod fastapi;
mod fastify;
mod fiber;
mod flask;
mod generic;
mod gin;
mod hono;
mod koa;
mod ktor;
mod laravel;
mod nestjs;
mod phoenix;
mod quarkus;
mod rails;
mod sinatra;
mod spring;
mod symfony;

use std::path::Path;

use crate::models::{ApiRoute, ScanConfig};
use crate::stack_detect;

use common::merge_routes;

type ExtractFn = fn(&Path, &ScanConfig) -> Vec<ApiRoute>;

fn dedicated_extractors() -> Vec<(&'static str, ExtractFn)> {
    vec![
        ("django", django::extract_django_routes),
        ("flask", flask::extract_flask_routes),
        ("express", express::extract_express_routes),
        ("nestjs", nestjs::extract_nestjs_routes),
        ("fastify", fastify::extract_fastify_routes),
        ("gin", gin::extract_gin_routes),
        ("spring", spring::extract_spring_routes),
        ("aspnet", aspnet::extract_aspnet_routes),
        ("laravel", laravel::extract_laravel_routes),
        ("rails", rails::extract_rails_routes),
        ("echo", echo::extract_echo_routes),
        ("fiber", fiber::extract_fiber_routes),
        ("chi", chi::extract_chi_routes),
        ("axum", axum::extract_axum_routes),
        ("actix", actix::extract_actix_routes),
        ("koa", koa::extract_koa_routes),
        ("hono", hono::extract_hono_routes),
        ("adonisjs", adonisjs::extract_adonisjs_routes),
        ("symfony", symfony::extract_symfony_routes),
        ("quarkus", quarkus::extract_quarkus_routes),
        ("ktor", ktor::extract_ktor_routes),
        ("sinatra", sinatra::extract_sinatra_routes),
        ("phoenix", phoenix::extract_phoenix_routes),
    ]
}

fn should_run_stack(stacks: &[String], name: &str) -> bool {
    stacks.is_empty() || stacks.iter().any(|s| s == name)
}

pub fn extract_api_routes(repo: &Path, config: &ScanConfig) -> (Vec<ApiRoute>, Vec<String>) {
    let stacks = if config.stack_hints.is_empty() {
        stack_detect::detect_stacks(repo)
    } else {
        config.stack_hints.clone()
    };

    let mut routes = Vec::new();
    let mut warnings = Vec::new();
    let mut used_dedicated = false;

    if should_run_stack(&stacks, "fastapi") {
        let (fastapi_routes, fastapi_warnings) = fastapi::extract_fastapi_routes(repo, config);
        if !fastapi_routes.is_empty() {
            used_dedicated = true;
        }
        routes.extend(fastapi_routes);
        warnings.extend(fastapi_warnings);
    }

    for (name, extractor) in dedicated_extractors() {
        if !should_run_stack(&stacks, name) {
            continue;
        }
        let found = extractor(repo, config);
        if !found.is_empty() {
            used_dedicated = true;
        }
        merge_routes(&mut routes, found);
    }

    let (style_routes, style_warnings) =
        crate::api_styles::extract_api_style_routes(repo, config, &stacks);
    if !style_routes.is_empty() {
        used_dedicated = true;
        merge_routes(&mut routes, style_routes);
    }
    warnings.extend(style_warnings);

    if !used_dedicated {
        warnings.push(
            "generic_extractor_used: no dedicated stack extractor matched — coverage may be limited"
                .into(),
        );
        merge_routes(&mut routes, generic::extract_generic_routes(repo, config));
    }

    if !stacks.is_empty() {
        warnings.push(format!("detected_stacks: {}", stacks.join(",")));
    }

    (routes, warnings)
}
