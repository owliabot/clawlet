//! Common types shared across Clawlet crates.

use std::fmt;

/// A 20-byte EVM address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Address(pub [u8; 20]);

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl From<[u8; 20]> for Address {
    fn from(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }
}

/// A 32-byte transaction hash.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TxHash(pub [u8; 32]);

impl fmt::Display for TxHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl From<[u8; 32]> for TxHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_display() {
        let addr = Address([0xab; 20]);
        assert!(addr.to_string().starts_with("0x"));
        assert_eq!(addr.to_string().len(), 42);
    }

    #[test]
    fn address_from_bytes() {
        let bytes = [1u8; 20];
        let addr: Address = bytes.into();
        assert_eq!(addr.0, bytes);
    }

    #[test]
    fn tx_hash_display() {
        let hash = TxHash([0xff; 32]);
        assert!(hash.to_string().starts_with("0x"));
        assert_eq!(hash.to_string().len(), 66);
    }
}
