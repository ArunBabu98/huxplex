use hux_crypto::{hash::shake::shake256_32, publickey::PublicKey};

#[derive(Debug, PartialEq)]
pub struct PeerId {
    pub id: [u8; 32],
}

impl PeerId {
    /// `PeerId = SHAKE-256(ML-DSA-44 public key)[..32]`.
    ///
    /// Self-certifying: identity **is** the key, so no registry can revoke, reassign or forge
    /// it ([wire spec §4](../../../docs/15-specifications/05-network-wire-protocol.md)).
    ///
    /// SHAKE lives in `hux-crypto` rather than here, so `hux-network` names no cryptographic
    /// vendor at all — the layering rule and the primitive-encapsulation rule (G1 · C4) pointing
    /// the same way.
    ///
    /// The previous implementation drove RustCrypto's `Shake256` incrementally and squeezed with
    /// `XofReader::read`, which always fills the buffer — deliberately not `std::io::Read::read`,
    /// whose short reads would have silently zero-padded a peer identity. The one-shot call below
    /// has no such failure mode: the length is a type parameter, so a short squeeze is not
    /// expressible. Output is unchanged, pinned by `hux-crypto`'s `tests/kat_hashes.rs`.
    pub fn from_ml_dsa_pk(pk: PublicKey) -> Self {
        PeerId {
            id: shake256_32(pk.bytes.as_slice()),
        }
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.id)
    }
}
