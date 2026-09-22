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

// ═════════════════════════════════════════════════════════════════════════════
//  zk-STARK  (Zero-Knowledge Scalable Transparent ARgument of Knowledge)
//  Hash-based proof system — no trusted setup, quantum-resistant.
//  Used by L6 Intent Layer for proof-of-task-completion.
//
//  Spec: proof size 100–200 KB, hash-based security (STARK, not SNARK)
//  Public inputs: task_hash, output_hash, agent_did, vc_id
//  Private inputs: full task execution trace
//
//  Expected API (src/crypto/zk_stark.rs):
//    pub const STARK_MIN_PROOF_BYTES: usize = 100_000;
//    pub const STARK_MAX_PROOF_BYTES: usize = 200_000;
//
//    pub fn stark_prove(
//        witness:      &[u8],      // private: task execution trace
//        public_input: &[u8],      // task_hash || output_hash || agent_did || vc_id
//    ) -> Result<StarkProof, StarkError>;
//
//    pub fn stark_verify(
//        proof:        &StarkProof,
//        public_input: &[u8],
//    ) -> bool;
//
//    pub fn stark_public_input(
//        task_hash:   [u8; 32],
//        output_hash: [u8; 32],
//        agent_did:   &[u8],
//        vc_id:       &[u8],
//    ) -> Vec<u8>;
// ═════════════════════════════════════════════════════════════════════════════
#[cfg(test)]
mod zk_stark_tests {
    use crate::zk_stark::{
        STARK_MAX_PROOF_BYTES, STARK_MIN_PROOF_BYTES, StarkError, stark_prove, stark_public_input,
        stark_verify,
    };

    // ── Canonical test fixtures ───────────────────────────────────────────────
    const TASK_HASH_A: [u8; 32] = [0xAAu8; 32];
    const OUTPUT_HASH_A: [u8; 32] = [0xBBu8; 32];
    const TASK_HASH_B: [u8; 32] = [0xCCu8; 32];
    const OUTPUT_HASH_B: [u8; 32] = [0xDDu8; 32];

    const AGENT_DID_A: &[u8] = b"did:huxplex:mainnet:0xdeadbeef01";
    const AGENT_DID_B: &[u8] = b"did:huxplex:mainnet:0xdeadbeef02";
    const VC_ID_A: &[u8] = b"vc:huxplex:work-visa:0xcafe0001";
    const VC_ID_B: &[u8] = b"vc:huxplex:work-visa:0xcafe0002";

    fn valid_witness_a() -> Vec<u8> {
        // Represents a minimal execution trace for task A
        let mut w = Vec::new();
        w.extend_from_slice(&TASK_HASH_A);
        w.extend_from_slice(&OUTPUT_HASH_A);
        w.extend_from_slice(b":execution-trace");
        w
    }

    fn valid_witness_b() -> Vec<u8> {
        let mut w = Vec::new();
        w.extend_from_slice(&TASK_HASH_B);
        w.extend_from_slice(&OUTPUT_HASH_B);
        w.extend_from_slice(b":execution-trace");
        w
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 1: Proof size constants per spec
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    #[ignore = "GATE: G10 — not implemented; see docs/16-action-plan.md"]
    fn test_proof_size_constants_match_spec() {
        // Spec: "Proof size: ~100–200 KB (zk-STARK, no trusted setup)"
        assert_eq!(
            STARK_MIN_PROOF_BYTES, 100_000,
            "STARK_MIN_PROOF_BYTES must be 100 KB per spec"
        );
        assert_eq!(
            STARK_MAX_PROOF_BYTES, 200_000,
            "STARK_MAX_PROOF_BYTES must be 200 KB per spec"
        );
        const {
            assert!(
                STARK_MIN_PROOF_BYTES < STARK_MAX_PROOF_BYTES,
                "Min proof bound must be less than max"
            )
        };
    }

    #[test]
    #[ignore = "GATE: G10 — not implemented; see docs/16-action-plan.md"]
    fn test_generated_proof_size_is_within_spec_bounds() {
        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let proof = stark_prove(&valid_witness_a(), &pub_input).expect("Valid witness must prove");

        assert!(
            proof.len() >= STARK_MIN_PROOF_BYTES,
            "zk-STARK proof ({} B) must be at least {} B",
            proof.len(),
            STARK_MIN_PROOF_BYTES
        );
        assert!(
            proof.len() <= STARK_MAX_PROOF_BYTES,
            "zk-STARK proof ({} B) must not exceed {} B",
            proof.len(),
            STARK_MAX_PROOF_BYTES
        );

        println!(
            "✓ zk-STARK proof size: {} KB (within {}-{} KB spec bounds)",
            proof.len() / 1000,
            STARK_MIN_PROOF_BYTES / 1000,
            STARK_MAX_PROOF_BYTES / 1000
        );
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 2: Completeness — valid witness produces verifiable proof
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    #[ignore = "GATE: G10 — not implemented; see docs/16-action-plan.md"]
    fn test_completeness_valid_witness_produces_valid_proof() {
        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let proof = stark_prove(&valid_witness_a(), &pub_input)
            .expect("Valid witness must produce a STARK proof");

        assert!(
            stark_verify(&proof, &pub_input),
            "STARK completeness: valid witness proof must verify"
        );
    }

    #[test]
    #[ignore = "GATE: G10 — not implemented; see docs/16-action-plan.md"]
    fn test_completeness_multiple_different_tasks_each_verify() {
        // (task_hash, output_hash, agent_did, vc_id)
        type TaskCase<'a> = ([u8; 32], [u8; 32], &'a [u8], &'a [u8]);
        let tasks: &[TaskCase] = &[
            (TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A),
            (TASK_HASH_B, OUTPUT_HASH_B, AGENT_DID_B, VC_ID_B),
        ];

        for (i, (th, oh, did, vc)) in tasks.iter().enumerate() {
            let pub_input = stark_public_input(*th, *oh, did, vc);
            let mut witness = Vec::new();
            witness.extend_from_slice(th);
            witness.extend_from_slice(oh);
            witness.extend_from_slice(b":trace");

            let proof = stark_prove(&witness, &pub_input).expect("Valid witness must prove");
            assert!(
                stark_verify(&proof, &pub_input),
                "Task {i} STARK proof must verify"
            );
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 3: Soundness — invalid/tampered inputs must fail verification
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    #[ignore = "GATE: G10 — not implemented; see docs/16-action-plan.md"]
    fn test_soundness_tampered_public_input_task_hash_fails() {
        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let proof = stark_prove(&valid_witness_a(), &pub_input).unwrap();

        // Tamper the task_hash in the public input
        let tampered_pub = stark_public_input(TASK_HASH_B, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        assert!(
            !stark_verify(&proof, &tampered_pub),
            "STARK soundness: tampered task_hash must fail verification"
        );
    }

    #[test]
    #[ignore = "GATE: G10 — not implemented; see docs/16-action-plan.md"]
    fn test_soundness_tampered_output_hash_fails() {
        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let proof = stark_prove(&valid_witness_a(), &pub_input).unwrap();

        let tampered_pub = stark_public_input(TASK_HASH_A, OUTPUT_HASH_B, AGENT_DID_A, VC_ID_A);
        assert!(
            !stark_verify(&proof, &tampered_pub),
            "STARK soundness: tampered output_hash must fail verification"
        );
    }

    #[test]
    #[ignore = "GATE: G10 — not implemented; see docs/16-action-plan.md"]
    fn test_soundness_tampered_agent_did_fails() {
        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let proof = stark_prove(&valid_witness_a(), &pub_input).unwrap();

        let tampered_pub = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_B, VC_ID_A);
        assert!(
            !stark_verify(&proof, &tampered_pub),
            "STARK soundness: tampered agent_did must fail verification — prevents identity fraud"
        );
    }

    #[test]
    #[ignore = "GATE: G10 — not implemented; see docs/16-action-plan.md"]
    fn test_soundness_tampered_vc_id_fails() {
        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let proof = stark_prove(&valid_witness_a(), &pub_input).unwrap();

        let tampered_pub = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_B);
        assert!(
            !stark_verify(&proof, &tampered_pub),
            "STARK soundness: tampered vc_id must fail verification"
        );
    }

    #[test]
    #[ignore = "GATE: G10 — not implemented; see docs/16-action-plan.md"]
    fn test_soundness_first_byte_flip_in_proof_fails() {
        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let mut proof = stark_prove(&valid_witness_a(), &pub_input).unwrap();

        proof.as_mut_bytes()[0] ^= 0x01;
        assert!(
            !stark_verify(&proof, &pub_input),
            "First-byte flip in STARK proof must fail verification"
        );
    }

    #[test]
    #[ignore = "GATE: G10 — not implemented; see docs/16-action-plan.md"]
    fn test_soundness_last_byte_flip_in_proof_fails() {
        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let mut proof = stark_prove(&valid_witness_a(), &pub_input).unwrap();

        let last = proof.len() - 1;
        proof.as_mut_bytes()[last] ^= 0xFF;
        assert!(
            !stark_verify(&proof, &pub_input),
            "Last-byte flip in STARK proof must fail verification"
        );
    }

    #[test]
    #[ignore = "GATE: G10 — not implemented; see docs/16-action-plan.md"]
    fn test_soundness_proof_a_does_not_verify_for_task_b() {
        // An agent must not reuse a proof from a previous task to claim completion of a new one.
        let pub_a = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let pub_b = stark_public_input(TASK_HASH_B, OUTPUT_HASH_B, AGENT_DID_A, VC_ID_A);

        let proof_a = stark_prove(&valid_witness_a(), &pub_a).unwrap();
        let proof_b = stark_prove(&valid_witness_b(), &pub_b).unwrap();

        // Cross-proof verification must fail
        assert!(
            !stark_verify(&proof_a, &pub_b),
            "Task A proof must not verify for task B public inputs"
        );
        assert!(
            !stark_verify(&proof_b, &pub_a),
            "Task B proof must not verify for task A public inputs"
        );

        println!("✓ STARK proof binding: cross-task verification rejected");
    }

    #[test]
    #[ignore = "GATE: G10 — not implemented; see docs/16-action-plan.md"]
    fn test_soundness_empty_witness_returns_error_or_invalid_proof() {
        // An empty execution trace cannot constitute a valid proof.
        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let result = stark_prove(b"", &pub_input);

        match result {
            Err(StarkError::InsufficientWitness) => {
                println!("✓ Empty witness correctly rejected with InsufficientWitness error");
            }
            Ok(proof) => {
                assert!(
                    !stark_verify(&proof, &pub_input),
                    "If prove succeeds on empty witness, verify must fail"
                );
            }
            Err(e) => {
                println!("✓ Empty witness rejected with error: {:?}", e);
            }
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 4: No trusted setup — STARK-specific properties
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    #[ignore = "GATE: G10 — not implemented; see docs/16-action-plan.md"]
    fn test_two_independent_proofs_of_same_task_both_verify() {
        // STARKs use public randomness (Fiat-Shamir). Two independently generated
        // proofs for the same (witness, public_input) should BOTH verify.
        // Unlike SNARKs, there is no per-proof trusted setup — any valid prover
        // can produce a valid proof.
        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);

        let proof1 = stark_prove(&valid_witness_a(), &pub_input).unwrap();
        let proof2 = stark_prove(&valid_witness_a(), &pub_input).unwrap();

        assert!(
            stark_verify(&proof1, &pub_input),
            "First STARK proof must verify"
        );
        assert!(
            stark_verify(&proof2, &pub_input),
            "Second independently generated STARK proof must verify"
        );

        println!("✓ No trusted setup: two independent proofs for same task both verify");
    }

    #[test]
    #[ignore = "GATE: G10 — not implemented; see docs/16-action-plan.md"]
    fn test_different_agents_same_task_hash_produce_different_proofs() {
        // Two different agents completing the same task (same task_hash) must produce
        // distinct proofs bound to their respective DIDs.
        let pub_a = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let pub_b = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_B, VC_ID_A);

        let proof_a = stark_prove(&valid_witness_a(), &pub_a).unwrap();
        let proof_b = stark_prove(&valid_witness_a(), &pub_b).unwrap();

        // Each proof verifies for its own public input
        assert!(
            stark_verify(&proof_a, &pub_a),
            "Agent A proof must verify with Agent A DID"
        );
        assert!(
            stark_verify(&proof_b, &pub_b),
            "Agent B proof must verify with Agent B DID"
        );

        // Neither proof verifies for the other's public input
        assert!(
            !stark_verify(&proof_a, &pub_b),
            "Agent A proof must not verify with Agent B DID"
        );
        assert!(
            !stark_verify(&proof_b, &pub_a),
            "Agent B proof must not verify with Agent A DID"
        );

        println!("✓ STARK agent-DID binding: cross-agent proof reuse correctly rejected");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 5: Zero-knowledge — proof reveals nothing about the witness
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    #[ignore = "GATE: G10 — not implemented; see docs/16-action-plan.md"]
    fn test_two_proofs_of_same_statement_have_different_bytes() {
        // Fiat-Shamir randomness ensures two independently generated proofs
        // for the same (witness, public_input) are bit-distinct — an observer
        // cannot track an agent across submissions by matching proof bytes.
        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);

        let proof1 = stark_prove(&valid_witness_a(), &pub_input).unwrap();
        let proof2 = stark_prove(&valid_witness_a(), &pub_input).unwrap();

        assert_ne!(
            proof1.as_bytes(),
            proof2.as_bytes(),
            "Two independently generated STARK proofs must have different bytes \
             (Fiat-Shamir randomness — prevents proof-linkability)"
        );

        println!("✓ STARK proofs are not proof-linkable: two submissions differ");
    }

    #[test]
    #[ignore = "GATE: G10 — not implemented; see docs/16-action-plan.md"]
    fn test_proof_does_not_leak_witness_bytes() {
        // The proof must not contain the raw witness as a substring.
        // A zk-STARK must not embed the private execution trace in the proof.
        let witness = valid_witness_a();
        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let proof = stark_prove(&witness, &pub_input).unwrap();

        let proof_bytes = proof.as_bytes();
        let witness_hex = hex::encode(&witness);

        // Check that the raw witness bytes do not appear verbatim in the proof
        let contains_witness = proof_bytes
            .windows(witness.len())
            .any(|w| w == witness.as_slice());

        assert!(
            !contains_witness,
            "STARK proof must not contain raw witness bytes — violates zero-knowledge property"
        );

        println!(
            "✓ STARK zero-knowledge: proof does not contain raw witness ({}-byte trace hidden)",
            witness.len()
        );
        let _ = witness_hex; // used only for debug context
    }

    #[test]
    #[ignore = "GATE: G10 — not implemented; see docs/16-action-plan.md"]
    fn test_different_witnesses_for_same_output_produce_different_proofs() {
        // Two agents arrive at the same output_hash via different execution paths.
        // Their proofs must differ — each proof commits to its own trace.
        let mut witness_alt = valid_witness_a();
        witness_alt.extend_from_slice(b":alternative-path");

        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);

        let proof_1 = stark_prove(&valid_witness_a(), &pub_input).unwrap();
        let proof_2 = stark_prove(&witness_alt, &pub_input).unwrap();

        // Both must verify (same public statement)
        assert!(
            stark_verify(&proof_1, &pub_input),
            "Primary witness proof must verify"
        );
        assert!(
            stark_verify(&proof_2, &pub_input),
            "Alternative witness proof must verify"
        );

        // But they must be distinct
        assert_ne!(
            proof_1.as_bytes(),
            proof_2.as_bytes(),
            "Different witness paths must produce different proofs"
        );

        println!("✓ Different execution paths → different proofs, both valid");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 6: Work-visa / escrow integration simulation
    //
    // Spec (L6 Intent Layer):
    //   1. Agent completes task T, produces execution trace W
    //   2. Agent submits stark_prove(W, pub_input) to escrow contract
    //   3. Escrow calls stark_verify(proof, pub_input)
    //   4. On success, escrowed HUX is released to agent
    //   5. On failure, HUX is returned to requester after timeout
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    #[ignore = "GATE: G10 — not implemented; see docs/16-action-plan.md"]
    fn test_work_visa_escrow_happy_path_agent_gets_paid() {
        // Agent A completes task, submits valid proof → escrow releases payment.
        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let proof = stark_prove(&valid_witness_a(), &pub_input)
            .expect("Agent must be able to prove task completion");

        // Escrow verifier
        let payment_released = stark_verify(&proof, &pub_input);
        assert!(
            payment_released,
            "Escrow must release payment on valid STARK proof (work-visa happy path)"
        );

        println!("✓ Work-visa escrow: valid proof → payment released");
    }

    #[test]
    #[ignore = "GATE: G10 — not implemented; see docs/16-action-plan.md"]
    fn test_work_visa_escrow_invalid_proof_payment_withheld() {
        // Agent submits a tampered proof → escrow refuses to release payment.
        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let mut proof = stark_prove(&valid_witness_a(), &pub_input).unwrap();

        // Agent tampers with their own proof (e.g., to claim a different output_hash)
        proof.as_mut_bytes()[42] ^= 0xFF;

        let payment_released = stark_verify(&proof, &pub_input);
        assert!(
            !payment_released,
            "Escrow must NOT release payment on tampered proof"
        );

        println!("✓ Work-visa escrow: tampered proof → payment withheld");
    }

    #[test]
    #[ignore = "GATE: G10 — not implemented; see docs/16-action-plan.md"]
    fn test_work_visa_agent_cannot_claim_another_agents_task_reward() {
        // Agent B tries to submit Agent A's valid proof to claim Agent A's reward.
        // The public input includes agent_did, so the proof is DID-bound.
        let pub_a = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let pub_b = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_B, VC_ID_A);

        // Agent A legitimately proves task A
        let proof_a = stark_prove(&valid_witness_a(), &pub_a).unwrap();

        // Agent B resubmits Agent A's proof against Agent B's DID
        let payment_to_b = stark_verify(&proof_a, &pub_b);
        assert!(
            !payment_to_b,
            "Agent B must not be able to claim Agent A's reward using Agent A's proof"
        );

        println!("✓ Work-visa: cross-agent proof reuse prevented — DID binding enforced");
    }

    #[test]
    #[ignore = "GATE: G10 — not implemented; see docs/16-action-plan.md"]
    fn test_work_visa_replayed_proof_from_previous_task_rejected() {
        // An agent tries to replay a proof from task A to claim payment for task B.
        // This tests that the vc_id and task_hash are both bound into the proof.
        let pub_task_a = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let pub_task_b = stark_public_input(TASK_HASH_B, OUTPUT_HASH_B, AGENT_DID_A, VC_ID_B);

        let proof_a = stark_prove(&valid_witness_a(), &pub_task_a).unwrap();

        // Attempt to use task A's proof for task B's escrow
        let payment_released = stark_verify(&proof_a, &pub_task_b);
        assert!(
            !payment_released,
            "Proof from task A must not unlock payment for task B — prevents replay across tasks"
        );

        println!("✓ Work-visa: task-replay attack prevented (task_hash + vc_id bound in proof)");
    }

    #[test]
    #[ignore = "GATE: G10 — not implemented; see docs/16-action-plan.md"]
    fn test_five_agents_five_tasks_all_complete_and_verify_independently() {
        // Simulates 5 concurrent AI agents each completing their own task.
        // This is the core L6 work-visa escrow scenario at small scale.
        let task_seeds: [(u8, u8); 5] = [
            (0x11, 0x21),
            (0x22, 0x32),
            (0x33, 0x43),
            (0x44, 0x54),
            (0x55, 0x65),
        ];

        let mut all_passed = true;
        for (i, (th_byte, oh_byte)) in task_seeds.iter().enumerate() {
            let task_hash: [u8; 32] = [*th_byte; 32];
            let output_hash: [u8; 32] = [*oh_byte; 32];
            let agent_did = format!("did:huxplex:mainnet:agent:{i}").into_bytes();
            let vc_id = format!("vc:huxplex:work-visa:{i}").into_bytes();

            let pub_input = stark_public_input(task_hash, output_hash, &agent_did, &vc_id);
            let mut witness = Vec::new();
            witness.extend_from_slice(&task_hash);
            witness.extend_from_slice(&output_hash);
            witness.extend_from_slice(b":trace");

            let proof = stark_prove(&witness, &pub_input)
                .expect("All agents must be able to prove their task");

            if !stark_verify(&proof, &pub_input) {
                all_passed = false;
                eprintln!("✗ Agent {i} task proof failed verification");
            }
        }

        assert!(all_passed, "All 5 agent task proofs must verify");
        println!("✓ 5 concurrent agent STARK proofs: all complete and verify independently");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 7: Edge cases and panic freedom
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    #[ignore = "GATE: G10 — not implemented; see docs/16-action-plan.md"]
    fn test_all_zero_public_inputs_no_panic_and_correctness() {
        // Degenerate inputs must not cause panic — must satisfy completeness.
        let pub_input =
            stark_public_input([0x00u8; 32], [0x00u8; 32], b"did:huxplex:zero", b"vc:zero");
        let mut witness = vec![0u8; 80];
        witness.extend_from_slice(b":trace");

        let result = stark_prove(&witness, &pub_input);
        match result {
            Ok(proof) => {
                // If prove succeeds on all-zero inputs, verify must also succeed
                assert!(
                    stark_verify(&proof, &pub_input),
                    "All-zero public input: prove/verify must be consistent"
                );
            }
            Err(e) => {
                println!(
                    "All-zero public inputs rejected at prove: {:?} (acceptable)",
                    e
                );
            }
        }
    }

    #[test]
    #[ignore = "GATE: G10 — not implemented; see docs/16-action-plan.md"]
    fn test_max_byte_public_inputs_no_panic_and_correctness() {
        let pub_input =
            stark_public_input([0xFFu8; 32], [0xFFu8; 32], b"did:huxplex:max", b"vc:max");
        let mut witness = vec![0xFFu8; 80];
        witness.extend_from_slice(b":trace");

        let result = stark_prove(&witness, &pub_input);
        match result {
            Ok(proof) => {
                assert!(
                    stark_verify(&proof, &pub_input),
                    "All-0xFF public input: prove/verify must be consistent"
                );
            }
            Err(e) => {
                println!("All-0xFF inputs rejected at prove: {:?} (acceptable)", e);
            }
        }
    }

    #[test]
    #[ignore = "GATE: G10 — not implemented; see docs/16-action-plan.md"]
    fn test_large_witness_no_panic_and_valid_proof_size() {
        // A large execution trace (e.g. a complex ML inference task) must still
        // produce a proof within the 100–200 KB spec bound.
        let large_witness = vec![0xABu8; 1024 * 512]; // 512 KB trace
        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);

        let result = stark_prove(&large_witness, &pub_input);
        match result {
            Ok(proof) => {
                assert!(
                    proof.len() >= STARK_MIN_PROOF_BYTES,
                    "Large-witness proof must meet minimum size"
                );
                assert!(
                    proof.len() <= STARK_MAX_PROOF_BYTES,
                    "Large-witness proof must not exceed {} B — STARK proof size is \
                     poly-logarithmic in trace length",
                    STARK_MAX_PROOF_BYTES
                );
                assert!(
                    stark_verify(&proof, &pub_input),
                    "Large-witness proof must verify"
                );
                println!(
                    "✓ 512 KB witness → {} KB proof (STARK log-size guarantee)",
                    proof.len() / 1000
                );
            }
            Err(e) => {
                println!(
                    "Large witness rejected: {:?} (acceptable if trace limit enforced)",
                    e
                );
            }
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 8: Type separation — STARK proof must not be mistaken for
    //          SLH-DSA, ML-DSA-44 or ML-KEM ciphertexts/signatures
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    #[ignore = "GATE: G10 — not implemented; see docs/16-action-plan.md"]
    fn test_stark_proof_size_distinct_from_all_other_l1_crypto_types() {
        use crate::{
            kem::CT_SIZE,
            slh_dsa::{SLH_DSA_PK_SIZE, SLH_DSA_SIG_SIZE, SLH_DSA_SK_SIZE},
        };

        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let proof = stark_prove(&valid_witness_a(), &pub_input).unwrap();
        let proof_len = proof.len();

        // STARK proof (100–200 KB) is orders of magnitude larger than all other types
        assert_ne!(
            proof_len, 2420,
            "STARK proof must not be same size as ML-DSA-44 sig"
        );
        assert_ne!(
            proof_len, 7856,
            "STARK proof must not be same size as SLH-DSA-128s sig"
        );
        assert_ne!(
            proof_len, CT_SIZE,
            "STARK proof must not be same size as ML-KEM-768 CT"
        );
        assert_ne!(
            proof_len, SLH_DSA_PK_SIZE,
            "STARK proof must not be same size as SLH-DSA-128s PK"
        );
        assert_ne!(
            proof_len, SLH_DSA_SK_SIZE,
            "STARK proof must not be same size as SLH-DSA-128s SK"
        );
        assert_ne!(
            proof_len, 1312,
            "STARK proof must not be same size as ML-DSA-44 PK"
        );

        println!(
            "✓ Type separation: STARK proof {} KB — no collision with ML-DSA-44 sig (2420 B), \
             SLH-DSA-128s sig (7856 B), ML-KEM-768 CT ({} B)",
            proof_len / 1000,
            CT_SIZE
        );

        let _ = (SLH_DSA_PK_SIZE, SLH_DSA_SK_SIZE, SLH_DSA_SIG_SIZE); // suppress unused warnings
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GROUP 9: Overhead documentation
    // ══════════════════════════════════════════════════════════════════════════

    #[test]
    #[ignore = "GATE: G10 — not implemented; see docs/16-action-plan.md"]
    fn test_overhead_documentation_vs_groth16_snark() {
        // zk-STARK vs Groth16 SNARK (reference: Ethereum zkEVM provers)
        //   Groth16 proof:   192 bytes  (trusted setup required)
        //   Plonk proof:     ~800 bytes (trusted setup required)
        //   zk-STARK proof:  100–200 KB (no trusted setup — transparent)
        //
        // Trade-off: larger proof, but:
        //   1. No trusted setup ceremony required
        //   2. Quantum-resistant (SHAKE-256 / FRI)
        //   3. Prover time is poly-log in trace length
        let groth16_proof_size: usize = 192;
        let plonk_proof_size: usize = 800;

        let pub_input = stark_public_input(TASK_HASH_A, OUTPUT_HASH_A, AGENT_DID_A, VC_ID_A);
        let proof = stark_prove(&valid_witness_a(), &pub_input).unwrap();

        println!("=== zk-STARK vs Classical ZK Systems ===");
        println!(
            "zk-STARK proof:      {:>8} B  (~{} KB)",
            proof.len(),
            proof.len() / 1000
        );
        println!(
            "Groth16 (SNARK):     {:>8} B  ({:.0}x smaller, but trusted setup + not PQ)",
            groth16_proof_size,
            proof.len() as f64 / groth16_proof_size as f64
        );
        println!(
            "Plonk (SNARK):       {:>8} B  ({:.0}x smaller, but trusted setup + not PQ)",
            plonk_proof_size,
            proof.len() as f64 / plonk_proof_size as f64
        );
        println!("Trusted setup:           None  (STARK is transparent — Fiat-Shamir + FRI)");
        println!("Quantum resistance:       Yes  (security from SHAKE-256 collision resistance)");
        println!("Use case: L6 work-visa task completion / AI agent escrow settlement");

        assert!(proof.len() >= STARK_MIN_PROOF_BYTES);
        assert!(proof.len() <= STARK_MAX_PROOF_BYTES);
    }
}
