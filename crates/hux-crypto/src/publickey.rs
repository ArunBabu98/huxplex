// crates/hux-crypto/src/publickey.rs
use crate::{
    error::{CryptoError, CryptoResult},
    sig::ml_dsa,
    signature::Signature,
    signaturescheme::SignatureSchemeId,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub scheme: SignatureSchemeId,
    pub bytes: Vec<u8>,
}

impl PublicKey {
    /// Verify a signature against this public key with an optional context
    pub fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
        context: Option<&[u8]>,
    ) -> CryptoResult<bool> {
        // 1. Scheme compatibility check
        if self.scheme != signature.scheme {
            return Err(CryptoError::SchemeMismatch {
                expected: self.scheme.clone(),
                actual: signature.scheme.clone(),
            });
        }

        // 2. Resolve the context (default to empty slice)
        let ctx_bytes = context.unwrap_or(&[]);

        match self.scheme {
            SignatureSchemeId::Dilithium2 => {
                ml_dsa::verify(&self.bytes, message, ctx_bytes, &signature.bytes)
            }
        }
    }
}
