//! LB-VRF (lattice-based verifiable random function) — API contract only. **Not implemented.**
//!
//! Intended for leader election and epoch randomness. Explicitly **deferred out of v1**
//! (docs/15-specifications/06-v1-scope.md §3: "LB-VRF / PQ-SSLE leader election —
//! classical fallback is fine for v1").
//!
//! `#[cfg(test)]`-only; exists so `lb_vrf_tests` type-checks against a fixed contract.
//!
//! Gate: **G6+**.

/// VRF output size per the Huxplex spec.
pub const LB_VRF_OUTPUT_SIZE: usize = 84;
/// Upper bound on proof size; must stay well inside a single gossip datagram.
pub const LB_VRF_PROOF_MAX: usize = 6144;

/// VRF public key.
pub type LbVrfPublicKey = [u8; 32];
/// VRF secret key.
pub type LbVrfSecretKey = [u8; 32];
/// VRF output (`beta`).
pub type LbVrfOutput = [u8; LB_VRF_OUTPUT_SIZE];

/// A VRF proof (`pi`). Variable length, bounded by [`LB_VRF_PROOF_MAX`].
///
/// A newtype rather than a bare `Vec<u8>`: `Vec` implements both `AsMut<[u8]>` and
/// `AsMut<Vec<u8>>`, so `proof.as_mut()` would be ambiguous at the call site.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LbVrfProof {
    bytes: Vec<u8>,
}

impl LbVrfProof {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Mutable access, used by soundness tests that tamper with proof bytes.
    #[allow(clippy::should_implement_trait)]
    pub fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

const UNIMPLEMENTED: &str = "LB-VRF is not implemented (gate G6+). See docs/16-action-plan.md.";

/// Derive a VRF keypair from a seed. MUST be deterministic in the seed.
pub fn lb_vrf_keygen(_seed: [u8; 32]) -> (LbVrfPublicKey, LbVrfSecretKey) {
    unimplemented!("{UNIMPLEMENTED}")
}

/// Evaluate the VRF over input `alpha`, returning `(output, proof)`.
pub fn lb_vrf_evaluate(_sk: &LbVrfSecretKey, _alpha: &[u8]) -> (LbVrfOutput, LbVrfProof) {
    unimplemented!("{UNIMPLEMENTED}")
}

/// Verify that `output` is the correct VRF evaluation of `alpha` under `pk`.
pub fn lb_vrf_verify(
    _pk: &LbVrfPublicKey,
    _alpha: &[u8],
    _output: &LbVrfOutput,
    _proof: &LbVrfProof,
) -> bool {
    unimplemented!("{UNIMPLEMENTED}")
}
