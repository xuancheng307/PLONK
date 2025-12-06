//! PLONK Demo Backend
//!
//! HTTP API server for the PLONK ZK-SNARK demonstration.

use axum::{
    routing::{get, post},
    Router,
};
use plonk_demo::api::{
    get_circuit_info, get_precomputed, get_srs_meta, health, prove, verify, ApiConfig, AppState,
};
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    let port: u16 = args
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);

    // Initialize application state
    let config = ApiConfig::default();
    let state = AppState::new(config).await;

    // Setup CORS
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Build router
    let api_routes = Router::new()
        .route("/api/health", get(health))
        .route("/api/prove", post(prove))
        .route("/api/verify", post(verify))
        .route("/api/precomputed", get(get_precomputed))
        .route("/api/circuit", get(get_circuit_info))
        .route("/api/srs_meta", get(get_srs_meta))
        .with_state(state);

    // Serve static files from the "static" directory
    let static_service = ServeDir::new("static");

    let app = Router::new()
        .merge(api_routes)
        .nest_service("/", static_service)
        .layer(cors);

    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("Starting server on http://{}", addr);
    println!();
    println!("Web Interface: http://localhost:{}/index.html", port);
    println!();
    println!("API Endpoints:");
    println!("  GET  /api/health      - Health check");
    println!("  POST /api/prove       - Generate a proof");
    println!("  POST /api/verify      - Verify a proof");
    println!("  GET  /api/precomputed - Get precomputed proofs");
    println!("  GET  /api/circuit     - Get circuit information");
    println!("  GET  /api/srs_meta    - Get SRS metadata");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
