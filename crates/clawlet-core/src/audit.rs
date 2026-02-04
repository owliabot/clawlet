//! Append-only audit logger.
//!
//! Records every wallet operation to a JSONL file for compliance and debugging.

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Errors from the audit logger.
#[derive(Debug, Error)]
pub enum AuditError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

/// An audit log event.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    /// Timestamp of the event.
    pub timestamp: DateTime<Utc>,
    /// Type of event (e.g. "transfer", "policy_check", "balance_query").
    pub event_type: String,
    /// Structured details about the event.
    pub details: serde_json::Value,
    /// Outcome of the event (e.g. "allowed", "denied", "error").
    pub outcome: String,
}

impl AuditEvent {
    /// Create a new audit event with the current timestamp.
    pub fn new(
        event_type: impl Into<String>,
        details: serde_json::Value,
        outcome: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            event_type: event_type.into(),
            details,
            outcome: outcome.into(),
        }
    }
}

/// Append-only JSONL audit logger.
pub struct AuditLogger {
    path: PathBuf,
    writer: BufWriter<File>,
}

impl AuditLogger {
    /// Create or open an audit log file for appending.
    pub fn new(path: &Path) -> Result<Self, AuditError> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            writer: BufWriter::new(file),
        })
    }

    /// Append an event to the audit log. Flushes after each write.
    pub fn log_event(&mut self, event: AuditEvent) -> Result<(), AuditError> {
        let line = serde_json::to_string(&event)?;
        writeln!(self.writer, "{line}")?;
        self.writer.flush()?;
        Ok(())
    }

    /// Get the path of the audit log file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn audit_event_serializes() {
        let event = AuditEvent::new("transfer", json!({"to": "0xabc", "amount": 100}), "allowed");
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"event_type\":\"transfer\""));
        assert!(json.contains("\"outcome\":\"allowed\""));
        assert!(json.contains("\"timestamp\""));
    }

    #[test]
    fn logger_writes_and_reads() {
        let dir = std::env::temp_dir().join(format!("clawlet_audit_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("audit.jsonl");

        {
            let mut logger = AuditLogger::new(&log_path).unwrap();
            logger
                .log_event(AuditEvent::new(
                    "transfer",
                    json!({"amount": 50}),
                    "allowed",
                ))
                .unwrap();
            logger
                .log_event(AuditEvent::new(
                    "policy_check",
                    json!({"token": "USDC"}),
                    "denied",
                ))
                .unwrap();
        }

        // Read back and verify
        let contents = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = contents.trim().lines().collect();
        assert_eq!(lines.len(), 2);

        // Each line should be valid JSON
        for line in &lines {
            let _: serde_json::Value = serde_json::from_str(line).unwrap();
        }

        // Cleanup
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn logger_appends_across_instances() {
        let dir = std::env::temp_dir().join(format!("clawlet_audit_append_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("audit.jsonl");

        // First instance
        {
            let mut logger = AuditLogger::new(&log_path).unwrap();
            logger
                .log_event(AuditEvent::new("first", json!({}), "ok"))
                .unwrap();
        }

        // Second instance — should append, not overwrite
        {
            let mut logger = AuditLogger::new(&log_path).unwrap();
            logger
                .log_event(AuditEvent::new("second", json!({}), "ok"))
                .unwrap();
        }

        let contents = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = contents.trim().lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"first\""));
        assert!(lines[1].contains("\"second\""));

        std::fs::remove_dir_all(&dir).ok();
    }
}
