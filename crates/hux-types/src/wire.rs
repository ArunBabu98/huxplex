//! Wire forms of the `hux-crypto` types that appear inside signed objects.
//!
//! `hux-crypto` has no serde dependency and should not grow one, so its types cross the wire
//! through these newtypes. Every wire-visible identifier is encoded by its **registry code**
//! (`SigRole::index`, `SuiteVersion::as_u16`, `SignatureSchemeId::as_u16`, `Network::code`),
//! never by serde's declaration-order variant index — reordering an enum must not be able to
//! change a byte on the wire.
//!
//! Decoding is fail-closed: an unregistered role, version, scheme or network, or a key or
//! signature whose length is not the one its scheme declares, is a decode error. Nothing is
//! defaulted, and nothing reaches verification that the registry would not resolve.
//!
//! # Layouts (postcard: varints for integers, length-prefixed byte strings) — frozen at G2a
//!
//! ```text
//! WireSuite     = role: u32 ‖ version: u16                 (ADR-0011 rule 3′: both axes)
//! WireNetwork   = code: u8                                   (1 = mainnet, 2 = testnet)
//! WirePublicKey = scheme: u16 ‖ len ‖ bytes                  (len = scheme's public-key size)
//! WireSignature = scheme: u16 ‖ len ‖ bytes                  (len = scheme's signature size)
//! ```

use hux_crypto::{
    context::Network,
    publickey::PublicKey,
    signature::Signature,
    signaturescheme::SignatureSchemeId,
    suite::{AlgoSuite, SigRole, SuiteVersion},
    traits,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

/// The `(role, version)` descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireSuite(pub AlgoSuite);

impl Serialize for WireSuite {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        (self.0.role.index(), self.0.version.as_u16()).serialize(s)
    }
}

impl<'de> Deserialize<'de> for WireSuite {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let (role, version) = <(u32, u16)>::deserialize(d)?;
        let role = SigRole::from_index(role)
            .ok_or_else(|| D::Error::custom(format!("unknown role {role}")))?;
        let version = SuiteVersion::from_u16(version)
            .ok_or_else(|| D::Error::custom(format!("unknown suite version {version}")))?;
        Ok(WireSuite(AlgoSuite::new(role, version)))
    }
}

/// A network, by registry code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireNetwork(pub Network);

impl Serialize for WireNetwork {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.code().serialize(s)
    }
}

impl<'de> Deserialize<'de> for WireNetwork {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let code = u8::deserialize(d)?;
        Network::from_code(code)
            .map(WireNetwork)
            .ok_or_else(|| D::Error::custom(format!("unknown network code {code}")))
    }
}

fn scheme<E: serde::de::Error>(raw: u16) -> Result<SignatureSchemeId, E> {
    SignatureSchemeId::from_u16(raw)
        .ok_or_else(|| E::custom(format!("unknown signature scheme {raw}")))
}

fn sizes<E: serde::de::Error>(scheme: SignatureSchemeId) -> Result<traits::SchemeSizes, E> {
    traits::verifier(scheme)
        .map(|v| v.sizes())
        .map_err(|e| E::custom(e.to_string()))
}

/// A public key: scheme, then exactly that scheme's key length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WirePublicKey(pub PublicKey);

impl Serialize for WirePublicKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        (self.0.scheme.as_u16(), &self.0.bytes).serialize(s)
    }
}

impl<'de> Deserialize<'de> for WirePublicKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let (raw, bytes) = <(u16, Vec<u8>)>::deserialize(d)?;
        let scheme = scheme::<D::Error>(raw)?;
        let expected = sizes::<D::Error>(scheme)?.public_key;
        if bytes.len() != expected {
            return Err(D::Error::custom(format!(
                "{scheme:?} public key must be {expected} bytes, got {}",
                bytes.len()
            )));
        }
        Ok(WirePublicKey(PublicKey { scheme, bytes }))
    }
}

/// A signature: scheme, then exactly that scheme's signature length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireSignature(pub Signature);

impl Serialize for WireSignature {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        (self.0.scheme.as_u16(), &self.0.bytes).serialize(s)
    }
}

impl<'de> Deserialize<'de> for WireSignature {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let (raw, bytes) = <(u16, Vec<u8>)>::deserialize(d)?;
        let scheme = scheme::<D::Error>(raw)?;
        let expected = sizes::<D::Error>(scheme)?.signature;
        if bytes.len() != expected {
            return Err(D::Error::custom(format!(
                "{scheme:?} signature must be {expected} bytes, got {}",
                bytes.len()
            )));
        }
        Ok(WireSignature(Signature { scheme, bytes }))
    }
}
