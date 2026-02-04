//! # clawlet_core
//!
//! Core library for **clawlet** — an agent-native wallet engine for OpenClaw.
//!
//! This crate provides key management, transaction signing, and chain-abstracted
//! wallet primitives designed for autonomous agent workflows.

/// Returns the library version string.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!version().is_empty());
    }
}
