//! The codec and the wire forms of the `hux-crypto` types, independent of any envelope.
//!
//! The envelope-level gate tests (G2-T1, G2-T2, G2-T4) are in `hux-network/tests/wire_encoding.rs`;
//! these pin the pieces every future signed type — G2b's included — is built from.

use hux_crypto::{
    context::Network,
    signature::Keypair,
    signaturescheme::SignatureSchemeId,
    suite::{AlgoSuite, SigRole, SuiteVersion},
};
use hux_types::{
    codec::{CodecError, from_canonical, to_canonical},
    wire::{WireNetwork, WirePublicKey, WireSignature, WireSuite},
};

const MAX: usize = 1 << 20;

#[test]
fn every_registered_descriptor_round_trips_by_registry_code() {
    for &role in SigRole::ALL {
        let suite = WireSuite(AlgoSuite::new(role, SuiteVersion::V1));
        let bytes = to_canonical(&suite);
        // Registry codes, not serde variant indices: role index then version, one byte each here.
        assert_eq!(
            bytes,
            vec![role.index() as u8, SuiteVersion::V1.as_u16() as u8]
        );
        assert_eq!(from_canonical::<WireSuite>(&bytes, MAX).unwrap(), suite);
    }
}

#[test]
fn networks_encode_by_code_and_zero_is_never_one() {
    for &network in Network::ALL {
        let bytes = to_canonical(&WireNetwork(network));
        assert_eq!(bytes, vec![network.code()]);
        assert_eq!(
            from_canonical::<WireNetwork>(&bytes, MAX).unwrap().0,
            network
        );
    }
    assert!(matches!(
        from_canonical::<WireNetwork>(&[0], MAX),
        Err(CodecError::Malformed(_))
    ));
}

#[test]
fn keys_and_signatures_of_both_schemes_round_trip_at_their_own_sizes() {
    let dsa = Keypair::generate(SignatureSchemeId::Dilithium2, [1u8; 32]).unwrap();
    let slh = Keypair::generate_from_seed(SignatureSchemeId::SlhDsa128s, &[2u8; 48]).unwrap();
    for kp in [&dsa, &slh] {
        let pk = WirePublicKey(kp.public_key().clone());
        let bytes = to_canonical(&pk);
        assert_eq!(from_canonical::<WirePublicKey>(&bytes, MAX).unwrap(), pk);

        let sig = WireSignature(kp.sign(b"m", None).unwrap());
        let bytes = to_canonical(&sig);
        assert_eq!(from_canonical::<WireSignature>(&bytes, MAX).unwrap(), sig);
    }
}

#[test]
fn a_key_declared_under_the_other_scheme_is_refused() {
    // An SLH-DSA key (32 bytes) relabelled as ML-DSA, and vice versa: each length is valid for
    // one scheme and wrong for the other.
    let slh = Keypair::generate_from_seed(SignatureSchemeId::SlhDsa128s, &[2u8; 48]).unwrap();
    let mut bytes = to_canonical(&WirePublicKey(slh.public_key().clone()));
    bytes[0] = SignatureSchemeId::Dilithium2.as_u16() as u8;
    assert!(matches!(
        from_canonical::<WirePublicKey>(&bytes, MAX),
        Err(CodecError::Malformed(_))
    ));
}

#[test]
fn the_size_bound_is_checked_before_decoding() {
    let bytes = to_canonical(&WireNetwork(Network::Mainnet));
    assert_eq!(
        from_canonical::<WireNetwork>(&bytes, 0),
        Err(CodecError::TooLarge { max: 0, actual: 1 })
    );
}
