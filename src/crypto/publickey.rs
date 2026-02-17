// src/crypto/publickey.rs
use libcrux_ml_dsa::ml_dsa_44;

use crate::crypto::{
    error::{CryptoError, CryptoResult},
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

        match self.scheme {
            SignatureSchemeId::Dilithium2 => {
                // 2. Prepare the Public Key (1312 bytes)
                let pk_bytes: [u8; 1312] = self.bytes.as_slice().try_into().map_err(|_| {
                    CryptoError::InvalidPublicKeySize(format!(
                        "Expected 1312 bytes, got {}",
                        self.bytes.len()
                    ))
                })?;
                let verification_key = ml_dsa_44::MLDSA44VerificationKey::new(pk_bytes);

                // 3. Prepare the Signature (2420 bytes)
                let sig_bytes: [u8; 2420] =
                    signature.bytes.as_slice().try_into().map_err(|_| {
                        CryptoError::InvalidSignatureLength {
                            expected: 2420,
                            actual: signature.bytes.len(),
                        }
                    })?;
                let mldsa_sig = ml_dsa_44::MLDSA44Signature::new(sig_bytes);

                // 4. Resolve the context (default to empty slice)
                let ctx_bytes = context.unwrap_or(&[]);

                // 5. Verify: (Key, Message, Context, Signature)
                let result = ml_dsa_44::verify(&verification_key, message, ctx_bytes, &mldsa_sig);

                Ok(result.is_ok())
            }
        }
    }
}
