use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::signaturescheme::SignatureSchemeId;

/// A private signing key.
///
/// # Secret hygiene
///
/// This type deliberately makes it hard to leak key material by accident:
///
/// * **`Debug` is redacted.** It never prints key bytes. Printing a secret is one careless
///   `tracing::debug!`, `dbg!`, or panic message away, and validator logs are routinely shipped
///   off-host.
/// * **The bytes are private.** Reading them requires [`PrivateKey::expose_secret`], whose name
///   is deliberately awkward so that every call site is greppable in review.
/// * **Zeroized on drop.** Key material is wiped rather than left in freed memory.
/// * **Equality is constant-time.** A byte-wise `==` short-circuits on the first differing byte
///   and is therefore a timing oracle.
///
/// See `docs/18-implementation-plan/01-g0-repository-health.md` (G0 item 7).
#[derive(Clone, ZeroizeOnDrop)]
pub struct PrivateKey {
    /// Which signature scheme this key belongs to. Not secret.
    #[zeroize(skip)]
    scheme: SignatureSchemeId,
    bytes: Vec<u8>,
}

impl PrivateKey {
    /// Wraps raw secret-key bytes.
    pub fn new(scheme: SignatureSchemeId, bytes: Vec<u8>) -> Self {
        PrivateKey { scheme, bytes }
    }

    /// The signature scheme this key belongs to.
    pub fn scheme(&self) -> &SignatureSchemeId {
        &self.scheme
    }

    /// Length of the secret key in bytes. Not secret — sizes are public parameters of the scheme.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the key is empty. Present because clippy requires it alongside [`Self::len`].
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Borrows the raw secret key bytes.
    ///
    /// **Every call site is a place a secret can escape.** Do not log, format, serialize, or
    /// copy the result into a longer-lived container. The name is intentionally unpleasant.
    pub fn expose_secret(&self) -> &[u8] {
        &self.bytes
    }
}

/// Redacted — never prints key material.
impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("scheme", &self.scheme)
            .field("bytes", &"<redacted>")
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// Constant-time equality.
///
/// Keys of different lengths compare unequal immediately; that is a public parameter of the
/// scheme, not a secret, so short-circuiting on it leaks nothing.
impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        if self.scheme != other.scheme || self.bytes.len() != other.bytes.len() {
            return false;
        }
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl Eq for PrivateKey {}

/// Explicit wipe, for callers that want to drop key material before the value goes out of scope.
impl PrivateKey {
    pub fn zeroize_now(&mut self) {
        self.bytes.zeroize();
    }
}
