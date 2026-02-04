//! API route definitions.
//!
//! Maps HTTP paths to handler functions.

use axum::middleware;
use axum::routing::{get, post};
use axum::Router;

use crate::auth::auth_middleware;
use crate::handlers::{
    handle_balance, handle_execute, handle_health, handle_skills, handle_transfer,
};
use crate::server::AppState;

/// Builds the axum router with all API routes.
///
/// Routes:
/// - `GET /health` — health check (no auth required)
/// - `GET /balance` — query ETH balance (auth required)
/// - `POST /transfer` — execute transfer (auth required)
/// - `GET /skills` — list AIS skills (auth required)
/// - `POST /execute` — execute an AIS skill (auth required)
pub fn build_router(state: AppState) -> Router {
    // Authenticated routes
    let protected = Router::new()
        .route("/balance", get(handle_balance))
        .route("/transfer", post(handle_transfer))
        .route("/skills", get(handle_skills))
        .route("/execute", post(handle_execute))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    // Public routes
    let public = Router::new().route("/health", get(handle_health));

    public.merge(protected).with_state(state)
}
