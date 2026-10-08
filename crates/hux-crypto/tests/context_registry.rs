//! **G1-T2 — cross-context replay fails, exhaustively.** Every ordered pair of registry contexts,
//! `dht:entry` included, across both networks — enumerated from `hux_crypto::context`, never
//! restated, so a context added to the registry joins the sweep automatically.
//!
//! Each context signs with the scheme its *role* resolves to in suite v1, the way production
//! would: ML-DSA-44 for the transaction and quorum contexts, SLH-DSA-128s for validator
//! registration and credentials. A signature from context `a` is then presented, with the same
//! key, under every other context `b`; it must never verify. Where `a` and `b` resolve to
//! different schemes the rejection is a `SchemeMismatch` error rather than `false` — still a
//! rejection, and still asserted.

use hux_crypto::{
    context::{self, GOSSIP_ROLE, Network, Purpose, RETIRED},
    signature::{Keypair, Signature},
    suite::{AlgoSuite, SigRole, SuiteVersion},
    traits,
};

const PAYLOAD: &[u8] = b"g1-t2: same payload under every context";

/// Gossip topics used to put the per-topic contexts into the sweep. `hux-network` owns the topic
/// set and sweeps it separately; these are its three shapes.
const TOPICS: &[&str] = &[
    "huxplex/shard/0/blocks",
    "huxplex/shard/0/mempool",
    "huxplex/shard/1/blocks",
    "huxplex/intents",
];

fn all_contexts() -> Vec<(String, SigRole)> {
    let mut out = Vec::new();
    for &network in Network::ALL {
        for &purpose in Purpose::ALL {
            out.push((
                String::from_utf8(context::context(network, purpose)).unwrap(),
                purpose.role(),
            ));
        }
        for topic in TOPICS {
            out.push((
                String::from_utf8(context::gossip_context(network.as_str(), topic)).unwrap(),
                GOSSIP_ROLE,
            ));
        }
    }
    out
}

fn keypair_for(role: SigRole) -> Keypair {
    let scheme = AlgoSuite::new(role, SuiteVersion::V1)
        .signature_scheme()
        .unwrap();
    let seed_len = traits::implementation(scheme).unwrap().sizes().seed;
    Keypair::generate_from_seed(scheme, &vec![role.index() as u8 + 1; seed_len]).unwrap()
}

#[test]
fn g1_t2_every_ordered_pair_of_contexts_is_separated() {
    let contexts = all_contexts();
    let keys: Vec<(SigRole, Keypair)> = SigRole::ALL.iter().map(|&r| (r, keypair_for(r))).collect();
    let key = |role: SigRole| &keys.iter().find(|(r, _)| *r == role).unwrap().1;

    let signatures: Vec<Signature> = contexts
        .iter()
        .map(|(ctx, role)| key(*role).sign(PAYLOAD, Some(ctx.as_bytes())).unwrap())
        .collect();

    let mut pairs = 0;
    for (i, (ctx_a, role_a)) in contexts.iter().enumerate() {
        let pk = key(*role_a).public_key();
        assert!(
            pk.verify(PAYLOAD, &signatures[i], Some(ctx_a.as_bytes()))
                .unwrap(),
            "{ctx_a} must self-verify"
        );
        for (j, (ctx_b, _)) in contexts.iter().enumerate() {
            if i == j {
                continue;
            }
            let accepted = pk
                .verify(PAYLOAD, &signatures[i], Some(ctx_b.as_bytes()))
                .unwrap_or(false);
            assert!(!accepted, "a {ctx_a} signature verified under {ctx_b}");
            pairs += 1;
        }
    }

    let n = contexts.len();
    assert_eq!(
        pairs,
        n * (n - 1),
        "the sweep must cover every ordered pair"
    );
}

#[test]
fn g1_t2_context_strings_are_unique_and_well_formed() {
    let contexts = all_contexts();
    for (i, (a, _)) in contexts.iter().enumerate() {
        assert!(a.is_ascii(), "{a} is not ASCII");
        assert!(a.starts_with("huxplex-mainnet:") || a.starts_with("huxplex-testnet:"));
        assert!(a.ends_with(":v1"), "{a} carries no version suffix");
        for (b, _) in &contexts[i + 1..] {
            assert_ne!(a, b, "two registry entries render to the same string");
        }
    }
}

#[test]
fn g1_t2_no_live_context_reuses_a_retired_one() {
    for (ctx, _) in all_contexts() {
        for retired in RETIRED {
            assert!(
                !ctx.contains(&format!(":{retired}:")),
                "{ctx} reissues the retired context {retired}"
            );
        }
    }
}

#[test]
fn g1_t2_network_is_never_baked_in() {
    // Spec §5 rule 2: every context is network-parameterised. Rendering for the two networks must
    // differ for every purpose, or one of them has a hard-coded network name.
    for &purpose in Purpose::ALL {
        assert_ne!(
            context::context(Network::Mainnet, purpose),
            context::context(Network::Testnet, purpose),
            "{purpose:?}"
        );
    }
    assert_eq!(
        Network::parse("devnet"),
        None,
        "unregistered networks fail closed"
    );
}

#[test]
fn context_roles_match_crypto_spec_section_5() {
    use Purpose::*;
    let expected = [
        (Transaction, SigRole::Transaction),
        (BlockPrePrepare, SigRole::QuorumCert),
        (BlockPrepare, SigRole::QuorumCert),
        (BlockCommit, SigRole::QuorumCert),
        (DhtEntry, SigRole::Transaction),
        (Intent, SigRole::Transaction),
        (Provenance, SigRole::Transaction),
        (ValidatorRegistration, SigRole::Identity),
        (Credential, SigRole::Governance),
    ];
    assert_eq!(expected.len(), Purpose::ALL.len());
    for (purpose, role) in expected {
        assert_eq!(purpose.role(), role, "{purpose:?}");
    }
    assert_eq!(GOSSIP_ROLE, SigRole::Transaction);
}

#[test]
fn context_strings_match_crypto_spec_section_5() {
    let m = |p| String::from_utf8(context::context(Network::Mainnet, p)).unwrap();
    assert_eq!(m(Purpose::Transaction), "huxplex-mainnet:tx:v1");
    assert_eq!(
        m(Purpose::BlockPrePrepare),
        "huxplex-mainnet:block:preprepare:v1"
    );
    assert_eq!(m(Purpose::BlockPrepare), "huxplex-mainnet:block:prepare:v1");
    assert_eq!(m(Purpose::BlockCommit), "huxplex-mainnet:block:commit:v1");
    assert_eq!(m(Purpose::DhtEntry), "huxplex-mainnet:dht:entry:v1");
    assert_eq!(m(Purpose::Intent), "huxplex-mainnet:intent:v1");
    assert_eq!(m(Purpose::Provenance), "huxplex-mainnet:provenance:v1");
    assert_eq!(
        m(Purpose::ValidatorRegistration),
        "huxplex-mainnet:validator:registration:v1"
    );
    assert_eq!(m(Purpose::Credential), "huxplex-mainnet:vc:v1");
    assert_eq!(
        context::gossip_context("testnet", "huxplex/intents"),
        b"huxplex-testnet:gossip:huxplex/intents:v1"
    );
}
