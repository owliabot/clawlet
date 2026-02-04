//! Request dispatch — routes incoming IPC requests to the appropriate handler.
//!
//! Replaces the old axum router with a simple match on [`RpcMethod`].

use tracing::{info, warn};

use crate::handlers::{self, BalanceQuery, ExecuteRequest, HandlerError, TransferRequest};
use crate::server::AppState;
use crate::types::{RpcMethod, RpcRequest, RpcResponse, RpcStatus};

/// Dispatch a single [`RpcRequest`] to the appropriate handler and produce an [`RpcResponse`].
///
/// Auth is checked here for all methods except [`RpcMethod::Health`].
/// Async handlers are executed via the provided tokio runtime handle.
pub fn dispatch(
    state: &AppState,
    request: &RpcRequest,
    rt: &tokio::runtime::Handle,
) -> RpcResponse {
    let method = match request.rpc_method() {
        Some(m) => m,
        None => {
            warn!(method = request.method, "unknown RPC method");
            return RpcResponse::error(RpcStatus::BadRequest, "unknown method");
        }
    };

    // Auth check for protected methods
    if method != RpcMethod::Health && !check_auth(state, request) {
        warn!("unauthorized request for {:?}", method);
        return RpcResponse::error(RpcStatus::Unauthorized, "unauthorized");
    }

    info!(?method, "dispatching RPC request");

    match method {
        RpcMethod::Health => {
            let result = handlers::handle_health(state);
            let json = serde_json::to_vec(&result).unwrap_or_default();
            RpcResponse::ok(&json)
        }
        RpcMethod::Balance => {
            let query: BalanceQuery = match serde_json::from_slice(request.payload_bytes()) {
                Ok(q) => q,
                Err(e) => {
                    return RpcResponse::error(
                        RpcStatus::BadRequest,
                        &format!("invalid payload: {e}"),
                    )
                }
            };
            match rt.block_on(handlers::handle_balance(state, query)) {
                Ok(resp) => {
                    let json = serde_json::to_vec(&resp).unwrap_or_default();
                    RpcResponse::ok(&json)
                }
                Err(e) => handler_error_to_response(e),
            }
        }
        RpcMethod::Transfer => {
            let req: TransferRequest = match serde_json::from_slice(request.payload_bytes()) {
                Ok(r) => r,
                Err(e) => {
                    return RpcResponse::error(
                        RpcStatus::BadRequest,
                        &format!("invalid payload: {e}"),
                    )
                }
            };
            match rt.block_on(handlers::handle_transfer(state, req)) {
                Ok(resp) => {
                    let json = serde_json::to_vec(&resp).unwrap_or_default();
                    RpcResponse::ok(&json)
                }
                Err(e) => handler_error_to_response(e),
            }
        }
        RpcMethod::Skills => match handlers::handle_skills(state) {
            Ok(resp) => {
                let json = serde_json::to_vec(&resp).unwrap_or_default();
                RpcResponse::ok(&json)
            }
            Err(e) => handler_error_to_response(e),
        },
        RpcMethod::Execute => {
            let req: ExecuteRequest = match serde_json::from_slice(request.payload_bytes()) {
                Ok(r) => r,
                Err(e) => {
                    return RpcResponse::error(
                        RpcStatus::BadRequest,
                        &format!("invalid payload: {e}"),
                    )
                }
            };
            match rt.block_on(handlers::handle_execute(state, req)) {
                Ok(resp) => {
                    let json = serde_json::to_vec(&resp).unwrap_or_default();
                    RpcResponse::ok(&json)
                }
                Err(e) => handler_error_to_response(e),
            }
        }
    }
}

/// Compare the request's auth token against the server's configured token.
///
/// If the server has no auth token configured (empty string), all requests pass.
fn check_auth(state: &AppState, request: &RpcRequest) -> bool {
    if state.auth_token.is_empty() {
        return true;
    }
    request.token_str() == state.auth_token
}

/// Map a [`HandlerError`] to an [`RpcResponse`] with appropriate status.
fn handler_error_to_response(err: HandlerError) -> RpcResponse {
    match err {
        HandlerError::BadRequest(msg) => RpcResponse::error(RpcStatus::BadRequest, &msg),
        HandlerError::NotFound(msg) => RpcResponse::error(RpcStatus::NotFound, &msg),
        HandlerError::Internal(msg) => RpcResponse::error(RpcStatus::InternalError, &msg),
    }
}
