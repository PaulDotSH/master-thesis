mod config;
mod db;
mod models;
mod routes;
mod schema;

use axum::{
    routing::get,
    Router,
};
use std::sync::Arc;
use tower_http::{cors::CorsLayer, services::ServeDir};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::Config;
use crate::db::create_pool;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "webpanel=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Config::from_file("config.toml")
        .or_else(|_| Config::from_file("webpanel/config.toml"))
        .expect("Failed to load config.toml");

    tracing::info!("Starting webpanel server on {}:{}", config.server_host, config.server_port);

    // Create database pool
    let pool = create_pool(&config.connection_string, config.max_connections).await?;
    let pool = Arc::new(pool);

    tracing::info!("Database connection pool created");

    // Build router
    let app = Router::new()
        // Dashboard/Stats API
        .route("/api/stats", get(routes::dashboard::get_stats))
        .route("/api/stats/severity", get(routes::dashboard::get_severity_distribution))
        .route("/api/stats/risk", get(routes::dashboard::get_risk_distribution))
        .route("/api/stats/build-rs", get(routes::dashboard::get_build_rs_stats))
        .route("/api/stats/top-downloaded", get(routes::dashboard::get_top_downloaded))
        .route("/api/stats/gitleaks-rules", get(routes::dashboard::get_gitleaks_by_rule))
        // Crates API
        .route("/api/crates", get(routes::crates::list_crates))
        .route("/api/crates/{id}", get(routes::crates::get_crate))
        .route("/api/crates/name/{name}", get(routes::crates::get_crate_by_name))
        // Dependencies API
        .route("/api/dependencies", get(routes::dependencies::list_dependencies))
        // Scan Results API
        .route("/api/scan-results", get(routes::scan_results::list_scan_results))
        .route("/api/scan-results/{id}", get(routes::scan_results::get_scan_result))
        // Cargo Audit API
        .route("/api/cargo-audit", get(routes::cargo_audit::list_cargo_audit))
        // Gitleaks API
        .route("/api/gitleaks", get(routes::gitleaks::list_gitleaks))
        // Metrics API
        .route("/api/metrics", get(routes::metrics::list_metrics))
        // Typosquat API
        .route("/api/typosquat", get(routes::typosquat::list_typosquat))
        // Static files (frontend)
        .fallback_service(ServeDir::new("static").append_index_html_on_directories(true))
        // State and middleware
        .with_state(pool)
        .layer(CorsLayer::permissive());

    // Start server
    let addr = format!("{}:{}", config.server_host, config.server_port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Server listening on {}", addr);

    axum::serve(listener, app).await?;

    Ok(())
}
