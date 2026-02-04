//! Encrypted keystore read/write.
//!
//! Manages creation, encryption, and decryption of private key files
//! following a format similar to Web3 Secret Storage.

/// Creates a new encrypted keystore file.
///
/// # Panics
/// Not yet implemented.
pub fn create(_path: &str, _password: &str) {
    todo!("M1-3: implement keystore creation")
}

/// Unlocks a keystore and returns the decrypted private key bytes.
///
/// # Panics
/// Not yet implemented.
pub fn unlock(_path: &str, _password: &str) -> Vec<u8> {
    todo!("M1-3: implement keystore unlock")
}
