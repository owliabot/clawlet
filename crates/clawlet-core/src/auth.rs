//! Authentication and session management for Clawlet.
//!
//! Implements password-based session authorization where humans grant
//! time-limited session tokens to AI agents. Agents never see the password.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Token prefix for Clawlet session tokens.
pub const TOKEN_PREFIX: &str = "clwt_";

/// Token length in random bytes (before base64 encoding).
const TOKEN_BYTES: usize = 32;

/// Token scope determines what operations a session can perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenScope {
    /// Read-only access: balance queries, skills listing.
    Read,
    /// Trade access: includes Read + transfer, execute (within policy).
    Trade,
    /// Admin access: includes Trade + auth management.
    Admin,
}

impl std::fmt::Display for TokenScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenScope::Read => write!(f, "read"),
            TokenScope::Trade => write!(f, "trade"),
            TokenScope::Admin => write!(f, "admin"),
        }
    }
}

impl std::str::FromStr for TokenScope {
    type Err = AuthError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "read" => Ok(TokenScope::Read),
            "trade" => Ok(TokenScope::Trade),
            "admin" => Ok(TokenScope::Admin),
            _ => Err(AuthError::InvalidScope(s.to_string())),
        }
    }
}

impl TokenScope {
    /// Check if this scope includes the required scope level.
    pub fn includes(&self, required: TokenScope) -> bool {
        *self >= required
    }
}

/// A session granted to an AI agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Agent identifier (e.g., "openclaw-main").
    pub id: String,
    /// Argon2id hash of the session token.
    #[serde(with = "token_hash_serde")]
    pub token_hash: [u8; 32],
    /// Permission scope for this session.
    pub scope: TokenScope,
    /// When the session was created.
    pub created_at: DateTime<Utc>,
    /// When the session expires.
    pub expires_at: DateTime<Utc>,
    /// Unix UID of the human who authorized this session.
    pub created_by_uid: u32,
    /// When the session was last used.
    pub last_used_at: DateTime<Utc>,
    /// Number of requests made with this session.
    pub request_count: u64,
}

/// Result of a successful [`SessionStore::grant`] call.
///
/// Contains the plaintext token together with key session metadata so that
/// callers do not need to re-query the store after granting.
#[derive(Debug, Clone)]
pub struct GrantResult {
    /// The plaintext session token to hand to the agent.
    pub token: String,
    /// When the session expires.
    pub expires_at: DateTime<Utc>,
    /// Permission scope granted.
    pub scope: TokenScope,
    /// When the session was created.
    pub created_at: DateTime<Utc>,
}

/// Custom serialization for token hash bytes.
mod token_hash_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(hash: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(hash))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(&s)
            .map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid token hash length: expected 32 bytes"))
    }
}

/// Grace period: expired sessions are kept for 7 days before removal.
const EXPIRY_GRACE_PERIOD: chrono::Duration = chrono::Duration::days(7);

/// Session store with optional disk persistence.
///
/// When created with [`SessionStore::with_persistence`], sessions are
/// automatically saved to a JSON file after every mutation (grant, revoke,
/// etc.) so they survive daemon restarts.
///
/// Sessions are keyed by the hex-encoded SHA-256 hash of their token,
/// allowing multiple sessions per agent ID.
#[derive(Debug, Default)]
pub struct SessionStore {
    /// Sessions keyed by hex-encoded token hash (unique per session).
    sessions: HashMap<String, Session>,
    /// Failed login attempts tracking for rate limiting.
    failed_attempts: HashMap<String, FailedAttempts>,
    /// Path to the sessions JSON file for persistence (None = in-memory only).
    persist_path: Option<PathBuf>,
}

/// Tracks failed authentication attempts for rate limiting.
#[derive(Debug, Clone)]
struct FailedAttempts {
    count: u32,
    #[allow(dead_code)]
    first_attempt: Instant,
    last_attempt: Instant,
}

/// Errors that can occur during authentication.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid token")]
    InvalidToken,
    #[error("token expired")]
    TokenExpired,
    #[error("insufficient scope: required {required}, actual {actual}")]
    InsufficientScope {
        required: TokenScope,
        actual: TokenScope,
    },
    #[error("incorrect password")]
    PasswordIncorrect,
    #[error("too many failed attempts, try again later")]
    TooManyAttempts,
    #[error("invalid scope: {0}")]
    InvalidScope(String),
    #[error("session not found: {0}")]
    SessionNotFound(String),
    #[error("hashing error: {0}")]
    HashingError(String),
}

impl SessionStore {
    /// Create a new empty session store (in-memory only).
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a session store that persists to disk.
    ///
    /// Loads existing (non-expired) sessions from `path` if the file exists.
    /// After every mutation, sessions are atomically written back.
    pub fn with_persistence(path: PathBuf) -> Self {
        let sessions = Self::load_from_file(&path).unwrap_or_default();
        Self {
            sessions,
            failed_attempts: HashMap::new(),
            persist_path: Some(path),
        }
    }

    /// Load sessions from a JSON file, filtering out entries past the grace period.
    ///
    /// Expired sessions are kept for [`EXPIRY_GRACE_PERIOD`] after their
    /// `expires_at` timestamp so they remain visible in listings / audits.
    fn load_from_file(path: &PathBuf) -> Option<HashMap<String, Session>> {
        let data = std::fs::read_to_string(path).ok()?;
        let sessions: HashMap<String, Session> = serde_json::from_str(&data).ok()?;
        let cutoff = Utc::now() - EXPIRY_GRACE_PERIOD;
        Some(
            sessions
                .into_iter()
                .filter(|(_, s)| s.expires_at > cutoff)
                .collect(),
        )
    }

    /// Atomically persist sessions to disk (write tmp + rename).
    fn persist(&self) {
        let Some(path) = &self.persist_path else {
            return;
        };
        let tmp_path = path.with_extension("json.tmp");
        match serde_json::to_string_pretty(&self.sessions) {
            Ok(data) => {
                if let Err(e) = std::fs::write(&tmp_path, &data) {
                    eprintln!(
                        "[clawlet] warn: failed to write sessions to {}: {e}",
                        tmp_path.display()
                    );
                    return;
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ =
                        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600));
                }
                if let Err(e) = std::fs::rename(&tmp_path, path) {
                    eprintln!("[clawlet] warn: failed to rename sessions file: {e}");
                }
            }
            Err(e) => {
                eprintln!("[clawlet] warn: failed to serialize sessions: {e}");
            }
        }
    }

    /// Grant a new session to an agent.
    ///
    /// Returns the plaintext token that should be given to the agent.
    /// The agent must present this token for all authenticated requests.
    pub fn grant(
        &mut self,
        id: &str,
        scope: TokenScope,
        expires_in: Duration,
        created_by_uid: u32,
    ) -> GrantResult {
        // Generate random token bytes
        let mut token_bytes = [0u8; TOKEN_BYTES];
        OsRng.fill_bytes(&mut token_bytes);

        // Create the full token with prefix
        let token = format!("{}{}", TOKEN_PREFIX, URL_SAFE_NO_PAD.encode(token_bytes));

        // Hash the token for storage (we use SHA-256 for token verification
        // since we're comparing against a stored hash, not protecting a password)
        let token_hash = hash_token(&token);

        let now = Utc::now();
        let expires_at = now + chrono::Duration::from_std(expires_in).unwrap_or_default();
        let session = Session {
            id: id.to_string(),
            token_hash,
            scope,
            created_at: now,
            expires_at,
            created_by_uid,
            last_used_at: now,
            request_count: 0,
        };

        // Use hex-encoded token hash as key (unique per session)
        let session_key = hex::encode(token_hash);
        self.sessions.insert(session_key, session);
        self.persist();

        GrantResult {
            token,
            expires_at,
            scope,
            created_at: now,
        }
    }

    /// Verify a token and return a mutable reference to the session.
    ///
    /// Updates `last_used_at` and `request_count` on successful verification.
    pub fn verify(&mut self, token: &str) -> Result<&Session, AuthError> {
        // Validate token format
        if !token.starts_with(TOKEN_PREFIX) {
            return Err(AuthError::InvalidToken);
        }

        let token_hash = hash_token(token);
        let session_key = hex::encode(token_hash);

        // Find matching session by key (O(1) lookup)
        let session = self
            .sessions
            .get_mut(&session_key)
            .ok_or(AuthError::InvalidToken)?;

        // Check expiration
        if Utc::now() > session.expires_at {
            return Err(AuthError::TokenExpired);
        }

        // Update usage stats
        session.last_used_at = Utc::now();
        session.request_count += 1;

        // Return immutable reference
        Ok(self.sessions.get(&session_key).unwrap())
    }

    /// Verify a token and check that it has the required scope.
    pub fn verify_with_scope(
        &mut self,
        token: &str,
        required_scope: TokenScope,
    ) -> Result<&Session, AuthError> {
        let session = self.verify(token)?;
        if !session.scope.includes(required_scope) {
            return Err(AuthError::InsufficientScope {
                required: required_scope,
                actual: session.scope,
            });
        }
        Ok(session)
    }

    /// Revoke all sessions for an agent ID.
    ///
    /// Returns true if any sessions were revoked, false if none existed.
    pub fn revoke(&mut self, agent_id: &str) -> bool {
        let before = self.sessions.len();
        self.sessions.retain(|_, s| s.id != agent_id);
        let revoked = self.sessions.len() != before;
        if revoked {
            self.persist();
        }
        revoked
    }

    /// Revoke a single session by its session key (hex-encoded token hash).
    ///
    /// Returns true if the session was found and removed.
    pub fn revoke_by_key(&mut self, session_key: &str) -> bool {
        let revoked = self.sessions.remove(session_key).is_some();
        if revoked {
            self.persist();
        }
        revoked
    }

    /// Revoke all sessions.
    ///
    /// Returns the number of sessions revoked.
    pub fn revoke_all(&mut self) -> usize {
        let count = self.sessions.len();
        self.sessions.clear();
        if count > 0 {
            self.persist();
        }
        count
    }

    /// List all sessions (including expired ones still within the grace period).
    pub fn list(&self) -> Vec<(&str, &Session)> {
        self.sessions.iter().map(|(k, v)| (k.as_str(), v)).collect()
    }

    /// Remove sessions that have been expired longer than the grace period (7 days).
    pub fn cleanup_expired(&mut self) {
        let cutoff = Utc::now() - EXPIRY_GRACE_PERIOD;
        let before = self.sessions.len();
        self.sessions
            .retain(|_, session| session.expires_at > cutoff);
        if self.sessions.len() != before {
            self.persist();
        }

        // Also cleanup old failed attempt records (older than 1 hour)
        let one_hour_ago = Instant::now() - Duration::from_secs(3600);
        self.failed_attempts
            .retain(|_, attempts| attempts.last_attempt > one_hour_ago);
    }

    /// Record a failed authentication attempt for rate limiting.
    pub fn record_failed_attempt(&mut self, identifier: &str) {
        let now = Instant::now();
        let entry = self
            .failed_attempts
            .entry(identifier.to_string())
            .or_insert_with(|| FailedAttempts {
                count: 0,
                first_attempt: now,
                last_attempt: now,
            });

        entry.count += 1;
        entry.last_attempt = now;
    }

    /// Check if an identifier is currently locked out due to too many failed attempts.
    pub fn is_locked_out(&self, identifier: &str, max_attempts: u32, lockout_minutes: u32) -> bool {
        if let Some(attempts) = self.failed_attempts.get(identifier) {
            if attempts.count >= max_attempts {
                let lockout_duration = Duration::from_secs(lockout_minutes as u64 * 60);
                if attempts.last_attempt.elapsed() < lockout_duration {
                    return true;
                }
            }
        }
        false
    }

    /// Clear failed attempts for an identifier (call after successful auth).
    pub fn clear_failed_attempts(&mut self, identifier: &str) {
        self.failed_attempts.remove(identifier);
    }

    /// Get the most recently created session for an agent ID (read-only).
    pub fn get(&self, agent_id: &str) -> Option<&Session> {
        self.sessions
            .values()
            .filter(|s| s.id == agent_id)
            .max_by_key(|s| s.created_at)
    }
}

/// Hash a password using Argon2id.
///
/// Returns the PHC-formatted hash string suitable for storage.
pub fn hash_password(password: &str) -> Result<String, AuthError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| AuthError::HashingError(e.to_string()))
}

/// Verify a password against an Argon2id hash.
pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

/// Hash a token using SHA-256 for fast comparison.
///
/// We use SHA-256 here instead of Argon2 because:
/// 1. Tokens are high-entropy random values, not human passwords
/// 2. We need fast verification for every API request
/// 3. The token is never transmitted to storage (only the hash is stored)
fn hash_token(token: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hash_verify() {
        let password = "test_password_123!";
        let hash = hash_password(password).unwrap();

        // Hash should be PHC format
        assert!(hash.starts_with("$argon2"));

        // Should verify correctly
        assert!(verify_password(password, &hash));

        // Wrong password should fail
        assert!(!verify_password("wrong_password", &hash));
    }

    #[test]
    fn test_session_grant_and_verify() {
        let mut store = SessionStore::new();

        let token = store
            .grant(
                "test-agent",
                TokenScope::Trade,
                Duration::from_secs(3600),
                1000,
            )
            .token;

        // Token should have correct prefix
        assert!(token.starts_with(TOKEN_PREFIX));
        assert!(token.len() > TOKEN_PREFIX.len() + 40); // prefix + base64

        // Should verify successfully
        let session = store.verify(&token).unwrap();
        assert_eq!(session.id, "test-agent");
        assert_eq!(session.scope, TokenScope::Trade);
        assert_eq!(session.created_by_uid, 1000);
        assert_eq!(session.request_count, 1);

        // Invalid token should fail
        assert!(matches!(
            store.verify("invalid_token"),
            Err(AuthError::InvalidToken)
        ));
    }

    #[test]
    fn test_session_expiry() {
        let mut store = SessionStore::new();

        // Grant a session that expires immediately
        let token = store
            .grant(
                "expired-agent",
                TokenScope::Read,
                Duration::from_secs(0),
                1000,
            )
            .token;

        // Wait a tiny bit to ensure expiration
        std::thread::sleep(Duration::from_millis(10));

        // Should fail with expired error
        assert!(matches!(store.verify(&token), Err(AuthError::TokenExpired)));
    }

    #[test]
    fn test_session_revoke() {
        let mut store = SessionStore::new();

        let token = store
            .grant("agent-1", TokenScope::Read, Duration::from_secs(3600), 1000)
            .token;

        // Verify it works
        assert!(store.verify(&token).is_ok());

        // Revoke by agent ID
        assert!(store.revoke("agent-1"));

        // Should no longer work
        assert!(matches!(store.verify(&token), Err(AuthError::InvalidToken)));

        // Revoking again should return false
        assert!(!store.revoke("agent-1"));
    }

    #[test]
    fn test_multiple_sessions_per_agent() {
        let mut store = SessionStore::new();

        let token1 = store
            .grant("agent-1", TokenScope::Read, Duration::from_secs(3600), 1000)
            .token;
        let token2 = store
            .grant(
                "agent-1",
                TokenScope::Trade,
                Duration::from_secs(7200),
                1000,
            )
            .token;

        // Both tokens should be valid
        assert!(store.verify(&token1).is_ok());
        assert!(store.verify(&token2).is_ok());

        // Both sessions should be in the store
        let agent_sessions: Vec<_> = store
            .list()
            .into_iter()
            .filter(|(_, s)| s.id == "agent-1")
            .collect();
        assert_eq!(agent_sessions.len(), 2);

        // get() should return the most recent one
        let latest = store.get("agent-1").unwrap();
        assert_eq!(latest.scope, TokenScope::Trade);
    }

    #[test]
    fn test_expired_session_within_grace_period() {
        let mut store = SessionStore::new();

        // Grant a session that expires immediately
        let token = store
            .grant("agent-1", TokenScope::Read, Duration::from_secs(0), 1000)
            .token;
        store.grant("agent-2", TokenScope::Read, Duration::from_secs(3600), 1000);

        std::thread::sleep(Duration::from_millis(10));

        // verify() should reject it
        assert!(matches!(store.verify(&token), Err(AuthError::TokenExpired)));

        // But cleanup should NOT remove it (within 7-day grace period)
        store.cleanup_expired();
        assert_eq!(store.list().len(), 2); // both still present
    }

    #[test]
    fn test_expired_session_past_grace_period() {
        let mut store = SessionStore::new();

        // Manually insert a session that expired 8 days ago
        let token_hash = hash_token("clwt_fake");
        let session_key = hex::encode(token_hash);
        let now = Utc::now();
        store.sessions.insert(
            session_key,
            Session {
                id: "old-agent".to_string(),
                token_hash,
                scope: TokenScope::Read,
                created_at: now - chrono::Duration::days(30),
                expires_at: now - chrono::Duration::days(8),
                created_by_uid: 1000,
                last_used_at: now - chrono::Duration::days(8),
                request_count: 0,
            },
        );
        store.grant("active", TokenScope::Read, Duration::from_secs(3600), 1000);

        assert_eq!(store.list().len(), 2);
        store.cleanup_expired();
        assert_eq!(store.list().len(), 1);
        assert!(store.get("active").is_some());
    }

    #[test]
    fn test_scope_check() {
        let mut store = SessionStore::new();

        // Grant a read-only session
        let token = store
            .grant(
                "read-agent",
                TokenScope::Read,
                Duration::from_secs(3600),
                1000,
            )
            .token;

        // Should work for Read scope
        assert!(store.verify_with_scope(&token, TokenScope::Read).is_ok());

        // Should fail for Trade scope
        assert!(matches!(
            store.verify_with_scope(&token, TokenScope::Trade),
            Err(AuthError::InsufficientScope { .. })
        ));

        // Grant an admin session
        let admin_token = store
            .grant(
                "admin-agent",
                TokenScope::Admin,
                Duration::from_secs(3600),
                1000,
            )
            .token;

        // Admin should have access to all scopes
        assert!(store
            .verify_with_scope(&admin_token, TokenScope::Read)
            .is_ok());
        assert!(store
            .verify_with_scope(&admin_token, TokenScope::Trade)
            .is_ok());
        assert!(store
            .verify_with_scope(&admin_token, TokenScope::Admin)
            .is_ok());
    }

    #[test]
    fn test_failed_attempts_lockout() {
        let mut store = SessionStore::new();

        let identifier = "test-client";
        let max_attempts = 5;
        let lockout_minutes = 15;

        // Should not be locked out initially
        assert!(!store.is_locked_out(identifier, max_attempts, lockout_minutes));

        // Record failures up to the limit
        for _ in 0..max_attempts {
            store.record_failed_attempt(identifier);
        }

        // Should now be locked out
        assert!(store.is_locked_out(identifier, max_attempts, lockout_minutes));

        // Clear failed attempts
        store.clear_failed_attempts(identifier);

        // Should no longer be locked out
        assert!(!store.is_locked_out(identifier, max_attempts, lockout_minutes));
    }

    #[test]
    fn test_token_scope_ordering() {
        assert!(TokenScope::Admin > TokenScope::Trade);
        assert!(TokenScope::Trade > TokenScope::Read);
        assert!(TokenScope::Admin.includes(TokenScope::Read));
        assert!(TokenScope::Trade.includes(TokenScope::Read));
        assert!(!TokenScope::Read.includes(TokenScope::Trade));
    }

    #[test]
    fn test_revoke_all() {
        let mut store = SessionStore::new();

        store.grant("agent-1", TokenScope::Read, Duration::from_secs(3600), 1000);
        store.grant(
            "agent-2",
            TokenScope::Trade,
            Duration::from_secs(3600),
            1000,
        );
        store.grant(
            "agent-3",
            TokenScope::Admin,
            Duration::from_secs(3600),
            1000,
        );

        assert_eq!(store.list().len(), 3);
        assert_eq!(store.revoke_all(), 3);
        assert_eq!(store.list().len(), 0);
    }

    #[test]
    fn test_cleanup_expired_within_grace() {
        let mut store = SessionStore::new();

        // Grant one that expires immediately and one that doesn't
        store.grant("expired", TokenScope::Read, Duration::from_secs(0), 1000);
        store.grant("active", TokenScope::Read, Duration::from_secs(3600), 1000);

        std::thread::sleep(Duration::from_millis(10));

        // Expired session is within 7-day grace period, so cleanup keeps it
        store.cleanup_expired();

        assert_eq!(store.list().len(), 2);
        assert!(store.get("active").is_some());
        assert!(store.get("expired").is_some());
    }

    #[test]
    fn test_token_format() {
        let mut store = SessionStore::new();
        let token = store
            .grant("test", TokenScope::Read, Duration::from_secs(3600), 1000)
            .token;

        // Should match expected format: clwt_ + base64url
        assert!(token.starts_with("clwt_"));
        let suffix = &token[5..];
        // Base64url should only contain alphanumeric, -, _
        assert!(suffix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn test_scope_from_str() {
        assert_eq!("read".parse::<TokenScope>().unwrap(), TokenScope::Read);
        assert_eq!("trade".parse::<TokenScope>().unwrap(), TokenScope::Trade);
        assert_eq!("admin".parse::<TokenScope>().unwrap(), TokenScope::Admin);
        assert_eq!("ADMIN".parse::<TokenScope>().unwrap(), TokenScope::Admin);
        assert!("invalid".parse::<TokenScope>().is_err());
    }

    #[test]
    fn test_persistence_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.json");

        // Grant sessions in a persistent store
        let token1;
        let token2;
        {
            let mut store = SessionStore::with_persistence(path.clone());
            token1 = store
                .grant(
                    "agent-1",
                    TokenScope::Trade,
                    Duration::from_secs(3600),
                    1000,
                )
                .token;
            token2 = store
                .grant(
                    "agent-2",
                    TokenScope::Admin,
                    Duration::from_secs(7200),
                    1001,
                )
                .token;
            assert_eq!(store.list().len(), 2);
        }

        // File should exist
        assert!(path.exists());

        // Load into a new store — sessions should survive
        {
            let mut store = SessionStore::with_persistence(path.clone());
            assert_eq!(store.list().len(), 2);

            // Tokens should still verify
            let s1 = store.verify(&token1).unwrap();
            assert_eq!(s1.id, "agent-1");
            assert_eq!(s1.scope, TokenScope::Trade);

            let s2 = store.verify(&token2).unwrap();
            assert_eq!(s2.id, "agent-2");
            assert_eq!(s2.scope, TokenScope::Admin);
        }
    }

    #[test]
    fn test_persistence_revoke() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.json");

        let token;
        {
            let mut store = SessionStore::with_persistence(path.clone());
            token = store
                .grant("agent-1", TokenScope::Read, Duration::from_secs(3600), 1000)
                .token;
            store.grant(
                "agent-2",
                TokenScope::Trade,
                Duration::from_secs(3600),
                1000,
            );
            store.revoke("agent-1");
        }

        // Reload — agent-1 should be gone, agent-2 should remain
        {
            let mut store = SessionStore::with_persistence(path.clone());
            assert_eq!(store.list().len(), 1);
            assert!(store.get("agent-2").is_some());
            assert!(store.verify(&token).is_err());
        }
    }

    #[test]
    fn test_persistence_recently_expired_sessions_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.json");

        {
            let mut store = SessionStore::with_persistence(path.clone());
            store.grant("expired", TokenScope::Read, Duration::from_secs(0), 1000);
            store.grant("active", TokenScope::Read, Duration::from_secs(3600), 1000);
        }

        std::thread::sleep(Duration::from_millis(10));

        // Reload — recently expired session is within grace period, should be kept
        {
            let store = SessionStore::with_persistence(path.clone());
            assert_eq!(store.list().len(), 2);
            assert!(store.get("active").is_some());
            assert!(store.get("expired").is_some());
        }
    }
}
