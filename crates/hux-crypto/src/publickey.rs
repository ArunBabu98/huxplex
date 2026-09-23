// crates/hux-crypto/src/publickey.rs
use crate::{
    error::{CryptoError, CryptoResult},
    signature::Signature,
    signaturescheme::SignatureSchemeId,
    traits,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub scheme: SignatureSchemeId,
    pub bytes: Vec<u8>,
}

impl PublicKey {
    /// Verify a signature against this public key with an optional context.
    ///
    /// Dispatches through the registry's trait, so no scheme is named here (G1 task C4) and no
    /// size literal appears (C6) — both come from the resolved implementation.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
        context: Option<&[u8]>,
    ) -> CryptoResult<bool> {
        // Scheme compatibility. Checked before dispatch so a mismatch is reported as itself
        // rather than surfacing as a length error from whichever scheme happened to be resolved.
        if self.scheme != signature.scheme {
            return Err(CryptoError::SchemeMismatch {
                expected: self.scheme,
                actual: signature.scheme,
            });
        }

        let implementation = traits::implementation(self.scheme)?;

        implementation.verify(
            &self.bytes,
            message,
            context.unwrap_or(&[]),
            &signature.bytes,
        )
    }
}
