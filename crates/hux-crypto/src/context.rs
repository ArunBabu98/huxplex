//! The context-string registry — [crypto spec §5](../../../docs/15-specifications/02-cryptography-spec.md),
//! as code.
//!
//! Every protocol signature is made over exactly one of these strings, and a signature valid
//! under one MUST NOT verify under any other. Until G1-T2 the registry existed only as prose and
//! as hand-written lists inside tests — which is how a retired context string was still being
//! "tested" as live. Now the sweep in `tests/context_registry.rs` enumerates [`Purpose::ALL`]
//! rather than restating it, so a context added here is covered the moment it exists.
//!
//! Every string has the shape `huxplex-{network}:{label}:v1`. `{network}` is never baked in
//! (spec §5 rule 2), and each purpose belongs to exactly one signature [`SigRole`] (rule 5).

use crate::suite::SigRole;

/// The networks a context can be bound to (spec §5: `{network}` ∈ {`mainnet`, `testnet`}).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    pub const ALL: &'static [Network] = &[Network::Mainnet, Network::Testnet];

    pub fn as_str(self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
        }
    }

    /// Fails closed on anything but the two registered networks.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "mainnet" => Some(Network::Mainnet),
            "testnet" => Some(Network::Testnet),
            _ => None,
        }
    }

    /// The wire code. **Frozen at G2a** — added, never renumbered — and, like every identifier
    /// in the registry, `0` is never assigned, so a zeroed field cannot be read as a network.
    pub const fn code(self) -> u8 {
        match self {
            Network::Mainnet => 1,
            Network::Testnet => 2,
        }
    }

    /// Resolves a wire code, failing closed on anything unregistered.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Network::Mainnet),
            2 => Some(Network::Testnet),
            _ => None,
        }
    }
}

impl core::fmt::Display for Network {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a signature is made for. One variant per row of spec §5, except gossip, which is
/// parameterised by topic and built with [`gossip_context`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Purpose {
    Transaction,
    BlockPrePrepare,
    BlockPrepare,
    BlockCommit,
    DhtEntry,
    Intent,
    Provenance,
    ValidatorRegistration,
    Credential,
}

impl Purpose {
    /// Every purpose, for conformance sweeps. Asserted exhaustive below.
    pub const ALL: &'static [Purpose] = &[
        Purpose::Transaction,
        Purpose::BlockPrePrepare,
        Purpose::BlockPrepare,
        Purpose::BlockCommit,
        Purpose::DhtEntry,
        Purpose::Intent,
        Purpose::Provenance,
        Purpose::ValidatorRegistration,
        Purpose::Credential,
    ];

    /// The `{label}` segment.
    pub const fn label(self) -> &'static str {
        match self {
            Purpose::Transaction => "tx",
            Purpose::BlockPrePrepare => "block:preprepare",
            Purpose::BlockPrepare => "block:prepare",
            Purpose::BlockCommit => "block:commit",
            Purpose::DhtEntry => "dht:entry",
            Purpose::Intent => "intent",
            Purpose::Provenance => "provenance",
            Purpose::ValidatorRegistration => "validator:registration",
            Purpose::Credential => "vc",
        }
    }

    /// The one signature role this context belongs to (spec §5 rule 5).
    pub const fn role(self) -> SigRole {
        match self {
            Purpose::Transaction | Purpose::DhtEntry | Purpose::Intent | Purpose::Provenance => {
                SigRole::Transaction
            }
            Purpose::BlockPrePrepare | Purpose::BlockPrepare | Purpose::BlockCommit => {
                SigRole::QuorumCert
            }
            Purpose::ValidatorRegistration => SigRole::Identity,
            Purpose::Credential => SigRole::Governance,
        }
    }
}

// Guards against a purpose being added to the enum but omitted from ALL, which would silently
// drop it from the G1-T2 sweep. Same pattern as `SigRole::ALL`.
const _: () = assert!(Purpose::ALL.len() == 9);

/// Gossip contexts belong to the `Transaction` role (spec §5).
pub const GOSSIP_ROLE: SigRole = SigRole::Transaction;

/// Context strings that have been retired. **Never reissued** (spec §5 rule 4): a retired string
/// may still appear in old signatures, so giving it a new meaning would make them valid for it.
pub const RETIRED: &[&str] = &[
    // ADR-0019: the transport handshake moved to TLS 1.3; network separation moved to ALPN.
    "tls:handshake",
];

/// `huxplex-{network}:{label}:v1`.
pub fn context(network: Network, purpose: Purpose) -> Vec<u8> {
    context_for(network.as_str(), purpose)
}

/// As [`context`], for callers that carry the network as a string (the pre-G2a envelopes).
pub fn context_for(network: &str, purpose: Purpose) -> Vec<u8> {
    format!("huxplex-{network}:{}:v1", purpose.label()).into_bytes()
}

/// `huxplex-{network}:gossip:{topic}:v1`, with `{topic}` the full topic string (spec §5 rule 1).
pub fn gossip_context(network: &str, topic: &str) -> Vec<u8> {
    format!("huxplex-{network}:gossip:{topic}:v1").into_bytes()
}
