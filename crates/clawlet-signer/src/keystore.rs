//! Encrypted keystore management.
//!
//! Encrypts and stores BIP-39 mnemonic phrases using scrypt + AES-256-GCM.
//! The keystore JSON format is chain-agnostic — it stores only the encrypted
//! mnemonic without any derived address.

use std::path::{Path, PathBuf};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use alloy::primitives::Address;
use k256::ecdsa::SigningKey;
use rand::RngCore;
use scrypt::scrypt;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use thiserror::Error;

use crate::hd;

/// Errors arising from keystore operations.
#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("keystore crypto error: {0}")]
    Crypto(String),

    #[error("invalid private key")]
    InvalidKey,

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("HD derivation error: {0}")]
    Hd(#[from] hd::HdError),
}

/// Result alias for keystore operations.
pub type Result<T> = std::result::Result<T, KeystoreError>;

/// Scrypt KDF parameters.
#[derive(Debug, Serialize, Deserialize)]
struct KdfParams {
    n: u32,
    r: u32,
    p: u32,
    dklen: u32,
    salt: String,
}

/// Cipher parameters.
#[derive(Debug, Serialize, Deserialize)]
struct CipherParams {
    nonce: String,
}

/// Crypto section of the keystore JSON.
#[derive(Debug, Serialize, Deserialize)]
struct CryptoSection {
    kdf: String,
    kdfparams: KdfParams,
    cipher: String,
    cipherparams: CipherParams,
    ciphertext: String,
    tag: String,
}

/// Top-level keystore JSON structure.
#[derive(Debug, Serialize, Deserialize)]
struct KeystoreJson {
    version: u32,
    crypto: CryptoSection,
    created_at: String,
}

/// Manages encrypted mnemonic files on disk.
pub struct Keystore;

impl Keystore {
    /// Creates a new keystore file with a freshly generated mnemonic.
    ///
    /// Returns the derived Ethereum address (index 0) and the path to the keystore JSON file.
    pub fn create(dir: &Path, password: &str) -> Result<(Address, PathBuf)> {
        let mnemonic = hd::generate_mnemonic();
        Self::create_from_mnemonic(dir, password, &mnemonic)
    }

    /// Creates a new keystore file from an existing mnemonic phrase.
    ///
    /// Returns the derived Ethereum address (index 0) and the path to the keystore JSON file.
    pub fn create_from_mnemonic(
        dir: &Path,
        password: &str,
        mnemonic: &str,
    ) -> Result<(Address, PathBuf)> {
        std::fs::create_dir_all(dir)?;

        // Derive address at index 0 for display
        let signing_key = hd::derive_key(mnemonic, 0)?;
        let address = public_key_to_address(&signing_key);

        // Encrypt the mnemonic
        let json = encrypt_mnemonic(mnemonic, password)?;
        let json_str = serde_json::to_string_pretty(&json)?;

        // Write to file named by UUID (chain-agnostic)
        let filename = format!("{}.json", uuid::Uuid::new_v4());
        let path = dir.join(&filename);
        std::fs::write(&path, json_str)?;

        Ok((address, path))
    }

    /// Unlocks a keystore file with the given password.
    ///
    /// Returns the decrypted mnemonic phrase.
    pub fn unlock(path: &Path, password: &str) -> Result<String> {
        let data = std::fs::read_to_string(path)?;
        let json: KeystoreJson = serde_json::from_str(&data)?;
        decrypt_mnemonic(&json, password)
    }

    /// Lists all keystore JSON files in a directory.
    ///
    /// Returns paths only — the keystore format is chain-agnostic and does not
    /// store derived addresses. Callers that need an address must unlock the
    /// keystore and derive it themselves.
    pub fn list(dir: &Path) -> Result<Vec<PathBuf>> {
        let mut results = Vec::new();

        if !dir.exists() {
            return Ok(results);
        }

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                results.push(path);
            }
        }

        Ok(results)
    }
}

/// Derives an Ethereum address from a signing key.
pub fn public_key_to_address(key: &SigningKey) -> Address {
    use k256::ecdsa::VerifyingKey;

    let verifying_key = VerifyingKey::from(key);
    let pubkey_bytes = verifying_key.to_encoded_point(false);
    let hash = Keccak256::digest(&pubkey_bytes.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    Address::from(addr)
}

/// Encrypt a mnemonic string using scrypt + AES-256-GCM.
fn encrypt_mnemonic(mnemonic: &str, password: &str) -> Result<KeystoreJson> {
    let mut rng = rand::thread_rng();

    // Generate random salt (32 bytes) and nonce (12 bytes for GCM)
    let mut salt = [0u8; 32];
    rng.fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);

    // Derive key with scrypt — N=2^17=131072, r=8, p=1 (~128 MB) per OWASP recommendations.
    let params =
        scrypt::Params::new(17, 8, 1, 32).map_err(|e| KeystoreError::Crypto(e.to_string()))?;
    let mut derived_key = [0u8; 32];
    scrypt(password.as_bytes(), &salt, &params, &mut derived_key)
        .map_err(|e| KeystoreError::Crypto(e.to_string()))?;

    // Encrypt with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|e| KeystoreError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext_with_tag = cipher
        .encrypt(nonce, mnemonic.as_bytes())
        .map_err(|e| KeystoreError::Crypto(e.to_string()))?;

    // AES-GCM appends 16-byte tag to ciphertext
    let tag_start = ciphertext_with_tag.len() - 16;
    let ciphertext = &ciphertext_with_tag[..tag_start];
    let tag = &ciphertext_with_tag[tag_start..];

    let now = chrono::Utc::now().to_rfc3339();

    Ok(KeystoreJson {
        version: 1,
        crypto: CryptoSection {
            kdf: "scrypt".to_string(),
            kdfparams: KdfParams {
                n: 131072,
                r: 8,
                p: 1,
                dklen: 32,
                salt: hex::encode(salt),
            },
            cipher: "aes-256-gcm".to_string(),
            cipherparams: CipherParams {
                nonce: hex::encode(nonce_bytes),
            },
            ciphertext: hex::encode(ciphertext),
            tag: hex::encode(tag),
        },
        created_at: now,
    })
}

/// Decrypt a mnemonic from keystore JSON.
fn decrypt_mnemonic(json: &KeystoreJson, password: &str) -> Result<String> {
    let salt = hex::decode(&json.crypto.kdfparams.salt)
        .map_err(|e| KeystoreError::Crypto(e.to_string()))?;
    let nonce_bytes = hex::decode(&json.crypto.cipherparams.nonce)
        .map_err(|e| KeystoreError::Crypto(e.to_string()))?;
    let ciphertext =
        hex::decode(&json.crypto.ciphertext).map_err(|e| KeystoreError::Crypto(e.to_string()))?;
    let tag = hex::decode(&json.crypto.tag).map_err(|e| KeystoreError::Crypto(e.to_string()))?;

    // Derive key with scrypt
    let log_n = (json.crypto.kdfparams.n as f64).log2() as u8;
    let params = scrypt::Params::new(
        log_n,
        json.crypto.kdfparams.r,
        json.crypto.kdfparams.p,
        json.crypto.kdfparams.dklen as usize,
    )
    .map_err(|e| KeystoreError::Crypto(e.to_string()))?;

    let mut derived_key = [0u8; 32];
    scrypt(password.as_bytes(), &salt, &params, &mut derived_key)
        .map_err(|e| KeystoreError::Crypto(e.to_string()))?;

    // Decrypt with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|e| KeystoreError::Crypto(e.to_string()))?;
    if nonce_bytes.len() != 12 {
        return Err(KeystoreError::Crypto(
            "invalid nonce length (expected 12 bytes)".into(),
        ));
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Reconstruct ciphertext + tag
    let mut ct_with_tag = ciphertext;
    ct_with_tag.extend_from_slice(&tag);

    let plaintext = cipher
        .decrypt(nonce, ct_with_tag.as_ref())
        .map_err(|_| KeystoreError::Crypto("decryption failed (wrong password?)".to_string()))?;

    String::from_utf8(plaintext)
        .map_err(|e| KeystoreError::Crypto(format!("invalid UTF-8 in decrypted mnemonic: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn create_and_unlock_keystore() {
        let dir = TempDir::new().unwrap();
        let password = "test-password-123";

        let (address, path) = Keystore::create(dir.path(), password).unwrap();
        assert!(path.exists());
        assert_ne!(address, Address::ZERO);

        // Unlock returns mnemonic
        let mnemonic = Keystore::unlock(&path, password).unwrap();
        // Derive key from mnemonic and verify address matches
        let key = hd::derive_key(&mnemonic, 0).unwrap();
        let derived = public_key_to_address(&key);
        assert_eq!(address, derived);
    }

    #[test]
    fn create_from_mnemonic_and_unlock() {
        let dir = TempDir::new().unwrap();
        let password = "test-password-123";
        let mnemonic = hd::generate_mnemonic();

        let (address, path) =
            Keystore::create_from_mnemonic(dir.path(), password, &mnemonic).unwrap();
        assert!(path.exists());

        let unlocked_mnemonic = Keystore::unlock(&path, password).unwrap();
        assert_eq!(mnemonic, unlocked_mnemonic);

        let key = hd::derive_key(&unlocked_mnemonic, 0).unwrap();
        assert_eq!(address, public_key_to_address(&key));
    }

    #[test]
    fn unlock_wrong_password_fails() {
        let dir = TempDir::new().unwrap();
        let (_address, path) = Keystore::create(dir.path(), "correct").unwrap();

        let result = Keystore::unlock(&path, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn list_keystores() {
        let dir = TempDir::new().unwrap();

        let (_addr1, _) = Keystore::create(dir.path(), "pw1").unwrap();
        let (_addr2, _) = Keystore::create(dir.path(), "pw2").unwrap();

        let list = Keystore::list(dir.path()).unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn list_empty_dir() {
        let dir = TempDir::new().unwrap();
        let list = Keystore::list(dir.path()).unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn list_nonexistent_dir() {
        let list = Keystore::list(Path::new("/tmp/does-not-exist-clawlet-test")).unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn public_key_to_address_deterministic() {
        let key = SigningKey::from_bytes(&[1u8; 32].into()).unwrap();
        let addr1 = public_key_to_address(&key);
        let addr2 = public_key_to_address(&key);
        assert_eq!(addr1, addr2);
        assert_ne!(addr1, Address::ZERO);
    }
}
