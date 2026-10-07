use rand::Rng;
use zeroize::Zeroizing;

use crate::{
    error::{CryptoError, CryptoResult},
    privatekey::PrivateKey,
    publickey::PublicKey,
    signaturescheme::SignatureSchemeId,
    traits::{self, SignatureScheme},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub scheme: SignatureSchemeId,
    pub bytes: Vec<u8>,
}

pub struct Keypair {
    publickey: PublicKey,
    privatekey: PrivateKey,
}

impl Keypair {
    /// Generates a keypair for `scheme` from a 32-byte seed — the length BIP32 derivation
    /// produces, and ML-DSA-44's keygen seed.
    ///
    /// A scheme whose seed is not 32 bytes (SLH-DSA-128s takes `3n = 48`) is refused with
    /// [`CryptoError::InvalidKeyLength`]; use [`Self::generate_from_seed`] for it.
    pub fn generate(scheme: SignatureSchemeId, seed: [u8; 32]) -> CryptoResult<Self> {
        Self::generate_from_seed(scheme, &seed)
    }

    /// Generates a keypair for `scheme` from a seed of whatever length the scheme declares.
    ///
    /// Dispatches through the registry's trait rather than matching on the scheme, and checks
    /// the seed against the scheme's own [`SchemeSizes`](traits::SchemeSizes) — so adding a
    /// scheme is a registry row plus an implementation, never an edit here (G1 tasks C4, C6).
    pub fn generate_from_seed(scheme: SignatureSchemeId, seed: &[u8]) -> CryptoResult<Self> {
        let (pk, sk) = keygen(traits::implementation(scheme)?, seed)?;

        Ok(Keypair {
            publickey: PublicKey { scheme, bytes: pk },
            privatekey: PrivateKey::new(scheme, sk),
        })
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.publickey
    }

    pub fn private_key(&self) -> &PrivateKey {
        &self.privatekey
    }

    pub fn sign(&self, message: &[u8], context: Option<&[u8]>) -> CryptoResult<Signature> {
        let scheme = self.public_key().scheme;
        let bytes = sign_hedged(
            traits::implementation(scheme)?,
            self.private_key().expose_secret(),
            message,
            context.unwrap_or(&[]),
        )?;

        Ok(Signature { scheme, bytes })
    }
}

/// Keygen against any registered scheme, with the seed length taken from the scheme itself.
fn keygen(implementation: &dyn SignatureScheme, seed: &[u8]) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    let expected = implementation.sizes().seed;
    if seed.len() != expected {
        return Err(CryptoError::InvalidKeyLength {
            expected,
            actual: seed.len(),
        });
    }
    implementation.generate(seed)
}

/// Hedged signing against any registered scheme.
///
/// Per-signature randomness comes from the system CSPRNG. Deterministic lattice signing plus
/// fault injection is a demonstrated key-recovery path (eprint 2025/2009), so hedging is
/// mandatory, not optional. Its *length* comes from the scheme's descriptor, so no nonce size is
/// named here (G1 task C6).
fn sign_hedged(
    implementation: &dyn SignatureScheme,
    secret_key: &[u8],
    message: &[u8],
    context: &[u8],
) -> CryptoResult<Vec<u8>> {
    let mut randomness = Zeroizing::new(vec![0u8; implementation.sizes().signing_randomness]);
    rand::rng().fill_bytes(&mut randomness);
    implementation.sign(secret_key, message, context, &randomness)
}

#[cfg(test)]
mod c6_tests {
    //! G1 task C6: *"a second signature scheme can be registered without editing any size
    //! literal."* A dummy scheme whose every size differs from ML-DSA-44's is driven through the
    //! same generic keygen and signing paths `Keypair` uses. If either path had a size baked in,
    //! the dummy's own length checks would reject what it was handed.

    use super::*;
    use crate::traits::{SchemeSizes, Signer, Verifier};

    const DUMMY: SchemeSizes = SchemeSizes {
        public_key: 7,
        secret_key: 11,
        signature: 13,
        seed: 5,
        signing_randomness: 3,
    };

    struct Dummy;

    impl Verifier for Dummy {
        fn sizes(&self) -> SchemeSizes {
            DUMMY
        }

        fn verify(&self, pk: &[u8], _: &[u8], _: &[u8], sig: &[u8]) -> CryptoResult<bool> {
            Ok(pk.len() == DUMMY.public_key && sig.len() == DUMMY.signature)
        }
    }

    impl Signer for Dummy {
        fn generate(&self, seed: &[u8]) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
            assert_eq!(
                seed.len(),
                DUMMY.seed,
                "keygen was handed a foreign seed size"
            );
            Ok((vec![1; DUMMY.public_key], vec![2; DUMMY.secret_key]))
        }

        fn sign(&self, sk: &[u8], _: &[u8], _: &[u8], randomness: &[u8]) -> CryptoResult<Vec<u8>> {
            assert_eq!(sk.len(), DUMMY.secret_key);
            assert_eq!(
                randomness.len(),
                DUMMY.signing_randomness,
                "the signing path named a nonce length instead of reading the descriptor"
            );
            Ok(vec![3; DUMMY.signature])
        }
    }

    #[test]
    fn c6_a_scheme_with_foreign_sizes_needs_no_size_edit() {
        let (pk, sk) = keygen(&Dummy, &[9u8; 5]).unwrap();
        assert_eq!((pk.len(), sk.len()), (DUMMY.public_key, DUMMY.secret_key));

        let sig = sign_hedged(&Dummy, &sk, b"m", b"c").unwrap();
        assert_eq!(sig.len(), DUMMY.signature);
        assert!(Dummy.verify(&pk, b"m", b"c", &sig).unwrap());
    }

    #[test]
    fn c6_keygen_rejects_a_seed_of_the_wrong_length_for_the_scheme() {
        // 32 bytes is right for ML-DSA-44 and wrong for this scheme — the check must come from
        // the scheme, not from a default.
        match keygen(&Dummy, &[0u8; 32]) {
            Err(CryptoError::InvalidKeyLength { expected, actual }) => {
                assert_eq!((expected, actual), (DUMMY.seed, 32));
            }
            other => panic!("expected InvalidKeyLength, got {other:?}"),
        }
    }
}
