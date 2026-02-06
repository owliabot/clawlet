//! Shared IPC message types for JSON-RPC communication.
//!
//! This module provides common types and constants used across the IPC layer.

use clawlet_core::auth::TokenScope;

/// RPC method discriminant — maps to the endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcMethod {
    Health,
    Balance,
    Transfer,
    Skills,
    Execute,
    /// Grant a new session token (Admin only).
    AuthGrant,
    /// List all active sessions (Admin only).
    AuthList,
    /// Revoke a session by agent ID (Admin only).
    AuthRevoke,
    /// Revoke all sessions (Admin only).
    AuthRevokeAll,
}

impl RpcMethod {
    /// Parse a method name string into an RpcMethod.
    pub fn parse_method(s: &str) -> Option<Self> {
        match s {
            "health" => Some(Self::Health),
            "balance" => Some(Self::Balance),
            "transfer" => Some(Self::Transfer),
            "skills" => Some(Self::Skills),
            "execute" => Some(Self::Execute),
            "auth.grant" => Some(Self::AuthGrant),
            "auth.list" => Some(Self::AuthList),
            "auth.revoke" => Some(Self::AuthRevoke),
            "auth.revoke_all" => Some(Self::AuthRevokeAll),
            _ => None,
        }
    }

    /// Get the method name as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Health => "health",
            Self::Balance => "balance",
            Self::Transfer => "transfer",
            Self::Skills => "skills",
            Self::Execute => "execute",
            Self::AuthGrant => "auth.grant",
            Self::AuthList => "auth.list",
            Self::AuthRevoke => "auth.revoke",
            Self::AuthRevokeAll => "auth.revoke_all",
        }
    }

    /// Get the required scope for this method (token-based auth).
    ///
    /// Returns `None` for methods that don't require token auth:
    /// - `Health`: public endpoint
    /// - `Auth*`: use password-based auth instead (handled in their handlers)
    pub fn required_scope(&self) -> Option<TokenScope> {
        match self {
            RpcMethod::Health => None, // Public endpoint
            RpcMethod::Balance | RpcMethod::Skills => Some(TokenScope::Read),
            RpcMethod::Transfer | RpcMethod::Execute => Some(TokenScope::Trade),
            // Auth methods use password verification, not token auth
            RpcMethod::AuthGrant
            | RpcMethod::AuthList
            | RpcMethod::AuthRevoke
            | RpcMethod::AuthRevokeAll => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_method_from_str() {
        assert_eq!(RpcMethod::parse_method("health"), Some(RpcMethod::Health));
        assert_eq!(RpcMethod::parse_method("balance"), Some(RpcMethod::Balance));
        assert_eq!(RpcMethod::parse_method("transfer"), Some(RpcMethod::Transfer));
        assert_eq!(RpcMethod::parse_method("skills"), Some(RpcMethod::Skills));
        assert_eq!(RpcMethod::parse_method("execute"), Some(RpcMethod::Execute));
        assert_eq!(
            RpcMethod::parse_method("auth.grant"),
            Some(RpcMethod::AuthGrant)
        );
        assert_eq!(RpcMethod::parse_method("auth.list"), Some(RpcMethod::AuthList));
        assert_eq!(
            RpcMethod::parse_method("auth.revoke"),
            Some(RpcMethod::AuthRevoke)
        );
        assert_eq!(
            RpcMethod::parse_method("auth.revoke_all"),
            Some(RpcMethod::AuthRevokeAll)
        );
        assert_eq!(RpcMethod::parse_method("unknown"), None);
    }

    #[test]
    fn test_method_as_str() {
        assert_eq!(RpcMethod::Health.as_str(), "health");
        assert_eq!(RpcMethod::Balance.as_str(), "balance");
        assert_eq!(RpcMethod::Transfer.as_str(), "transfer");
        assert_eq!(RpcMethod::Skills.as_str(), "skills");
        assert_eq!(RpcMethod::Execute.as_str(), "execute");
        assert_eq!(RpcMethod::AuthGrant.as_str(), "auth.grant");
        assert_eq!(RpcMethod::AuthList.as_str(), "auth.list");
        assert_eq!(RpcMethod::AuthRevoke.as_str(), "auth.revoke");
        assert_eq!(RpcMethod::AuthRevokeAll.as_str(), "auth.revoke_all");
    }

    #[test]
    fn test_method_required_scope() {
        use clawlet_core::auth::TokenScope;

        assert_eq!(RpcMethod::Health.required_scope(), None);
        assert_eq!(RpcMethod::Balance.required_scope(), Some(TokenScope::Read));
        assert_eq!(RpcMethod::Skills.required_scope(), Some(TokenScope::Read));
        assert_eq!(
            RpcMethod::Transfer.required_scope(),
            Some(TokenScope::Trade)
        );
        assert_eq!(RpcMethod::Execute.required_scope(), Some(TokenScope::Trade));
        assert_eq!(RpcMethod::AuthGrant.required_scope(), None);
        assert_eq!(RpcMethod::AuthList.required_scope(), None);
        assert_eq!(RpcMethod::AuthRevoke.required_scope(), None);
        assert_eq!(RpcMethod::AuthRevokeAll.required_scope(), None);
    }

    #[test]
    fn test_method_roundtrip() {
        let methods = [
            RpcMethod::Health,
            RpcMethod::Balance,
            RpcMethod::Transfer,
            RpcMethod::Skills,
            RpcMethod::Execute,
            RpcMethod::AuthGrant,
            RpcMethod::AuthList,
            RpcMethod::AuthRevoke,
            RpcMethod::AuthRevokeAll,
        ];

        for method in methods {
            let s = method.as_str();
            let parsed = RpcMethod::parse_method(s);
            assert_eq!(parsed, Some(method), "roundtrip failed for {:?}", method);
        }
    }
}
