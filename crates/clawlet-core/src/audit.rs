//! Append-only audit logger.
//!
//! Records every wallet operation to a JSONL file for compliance and debugging.

/// An audit log entry.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    /// ISO-8601 timestamp.
    pub timestamp: String,
    /// The action performed (e.g. "transfer", "balance_query").
    pub action: String,
    /// Whether the action was allowed by policy.
    pub allowed: bool,
    /// Optional details / context.
    pub details: String,
}

/// Appends an entry to the audit log.
///
/// # Panics
/// Not yet implemented.
pub fn append(_entry: AuditEntry) {
    todo!("M1-2: implement audit log writer")
}
