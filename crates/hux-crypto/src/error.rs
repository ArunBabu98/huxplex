use thiserror::Error;

use crate::signaturescheme::SignatureSchemeId;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid signature scheme: expected {expected:?}, got {actual:?}")]
    SchemeMismatch {
        expected: SignatureSchemeId,
        actual: SignatureSchemeId,
    },

    #[error("Signature verification failed")]
    VerificationFailed,

    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("Invalid signature length: expected {expected}, got {actual}")]
    InvalidSignatureLength { expected: usize, actual: usize },

    #[error("Invalid SK size: {0}")]
    InvalidSecretKeySize(String),

    #[error("Invalid PK size: {0}")]
    InvalidPublicKeySize(String),

    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// A registry failure: unknown `(role, version)`, an unimplemented scheme, or a role /
    /// version confusion. Kept as its own variant so a registry rejection is never flattened
    /// into a generic verification failure — the distinction is what makes G1-T4 and G1-T6
    /// testable.
    #[error("algorithm suite error: {0}")]
    Suite(#[from] crate::suite::SuiteError),
}

pub type CryptoResult<T> = Result<T, CryptoError>;
