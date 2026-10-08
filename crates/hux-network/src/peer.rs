use hux_crypto::{hash::shake::shake256_32, publickey::PublicKey};
use libp2p::multihash::Multihash;

/// Length of a Huxplex `PeerId`: a SHAKE-256 squeeze of 32 bytes.
pub const PEER_ID_LEN: usize = 32;

/// The multihash code for *identity* — "these bytes are the identifier" (ADR-0021 rule I2).
const MULTIHASH_IDENTITY: u64 = 0x00;

/// ADR-0021 rule **I4**: libp2p accepts identity-coded multihashes only up to 42 bytes
/// (`MAX_INLINE_KEY_LENGTH`). A future hash change that grew the `PeerId` past that must fail
/// the build, not the network.
const _: () = assert!(PEER_ID_LEN <= 42);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId {
    pub id: [u8; PEER_ID_LEN],
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

    /// The libp2p encoding of this identity: `0x00 ‖ 0x20 ‖ id` — an identity-coded multihash
    /// ([ADR-0021](../../../docs/adr/0021-peer-identity-across-libp2p.md)).
    ///
    /// **One identity, two encodings** (rule I1). This is not a second identity derived from a
    /// libp2p key; it is these 32 bytes, framed the way libp2p's swarm, GossipSub and Kademlia
    /// expect. Total and lossless (rule I3).
    pub fn to_libp2p(&self) -> libp2p::PeerId {
        let multihash = Multihash::wrap(MULTIHASH_IDENTITY, &self.id)
            .expect("PEER_ID_LEN fits a 64-byte multihash");
        libp2p::PeerId::from_multihash(multihash)
            .expect("identity multihashes up to 42 bytes are accepted (I4 is asserted above)")
    }

    /// The inverse of [`Self::to_libp2p`]. `None` for any libp2p `PeerId` that is not a
    /// re-encoding of a Huxplex one — rule I1: nothing may hold such a `PeerId`, so it is refused
    /// rather than mapped.
    pub fn from_libp2p(peer: &libp2p::PeerId) -> Option<Self> {
        let multihash: &Multihash<64> = peer.as_ref();
        if multihash.code() != MULTIHASH_IDENTITY {
            return None;
        }
        let id = multihash.digest().try_into().ok()?;
        Some(PeerId { id })
    }
}
