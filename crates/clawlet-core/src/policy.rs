//! Policy engine — evaluates rules against requested operations.
//!
//! Checks transfer limits, allowed tokens, and other configurable constraints.

/// Result of a policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// The operation is allowed.
    Allow,
    /// The operation is denied, with a reason.
    Deny(String),
}

/// Evaluates a policy against a transfer request.
///
/// # Panics
/// Not yet implemented.
pub fn evaluate() -> PolicyDecision {
    todo!("M1-1: implement policy evaluation")
}
