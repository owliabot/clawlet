//! Signing interface.
//!
//! Provides a unified trait for signing raw messages and transactions.

/// A signer that can sign arbitrary bytes.
pub trait Signer {
    /// Sign the given message bytes, returning a 65-byte signature.
    fn sign(&self, message: &[u8]) -> Vec<u8>;

    /// Returns the signer's address.
    fn address(&self) -> clawlet_core::types::Address;
}
