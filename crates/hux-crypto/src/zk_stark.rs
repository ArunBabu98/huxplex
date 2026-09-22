//! zk-STARK proof-of-task-completion — API contract only. **Not implemented.**
//!
//! Hash-based, transparent (no trusted setup), PQ-safe. Used by the agent economy for
//! verifiable task completion, and **only** for tasks with a checkable specification —
//! see `docs/04-ai-economy/autonomous-commerce.md` on scoping this honestly.
//!
//! Explicitly **deferred out of v1** (docs/15-specifications/06-v1-scope.md §3).
//! `#[cfg(test)]`-only; exists so `zk_stark_tests` type-checks against a fixed contract.
//!
//! Gate: **G10**.

/// Lower bound on a well-formed proof (spec: 100–200 KB).
pub const STARK_MIN_PROOF_BYTES: usize = 100_000;
/// Upper bound on a well-formed proof (spec: 100–200 KB).
pub const STARK_MAX_PROOF_BYTES: usize = 200_000;

const UNIMPLEMENTED: &str = "zk-STARK is not implemented (gate G10). See docs/16-action-plan.md.";

/// A STARK proof over a task execution trace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StarkProof {
    bytes: Vec<u8>,
}

impl StarkProof {
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
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

/// Why proving failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StarkError {
    /// The witness was empty or too short to constitute an execution trace.
    InsufficientWitness,
    /// The witness does not satisfy the claimed public input.
    WitnessMismatch,
    /// Proving exceeded its resource budget.
    ProverBudgetExceeded,
}

/// Bind the public inputs into their canonical byte encoding:
/// `task_hash || output_hash || agent_did || vc_id`.
pub fn stark_public_input(
    _task_hash: [u8; 32],
    _output_hash: [u8; 32],
    _agent_did: &[u8],
    _vc_id: &[u8],
) -> Vec<u8> {
    unimplemented!("{UNIMPLEMENTED}")
}

/// Prove that `witness` is a valid execution trace for `public_input`.
pub fn stark_prove(_witness: &[u8], _public_input: &[u8]) -> Result<StarkProof, StarkError> {
    unimplemented!("{UNIMPLEMENTED}")
}

/// Verify `proof` against `public_input`.
pub fn stark_verify(_proof: &StarkProof, _public_input: &[u8]) -> bool {
    unimplemented!("{UNIMPLEMENTED}")
}
