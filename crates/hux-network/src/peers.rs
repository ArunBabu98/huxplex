//! The peer lifecycle — task **N8**, [wire spec §3](../../../docs/15-specifications/05-network-wire-protocol.md),
//! and the Huxplex half of peer scoring (**N11**).
//!
//! ```text
//!   Disconnected ──dial──► Connecting ──► Handshaking ──TLS + PeerId match──► Identified
//!        ▲                                    │ fail (backoff)                    │ first
//!        └────────────────────────────────────┴──── disconnect ◄──── Active ◄────┘ traffic
//!                                                                      │ score ≤ ban threshold
//!                                                                      ▼
//!                                                                   Banned (until expiry)
//! ```
//!
//! The rule that matters most: **no application message is processed from a peer that has not
//! reached `Identified`** ([`PeerTable::may_process`]). The transport enforces it structurally —
//! it yields no connection, and so no stream, before mutual TLS authentication — and the node
//! checks it again on every message, so a future transport cannot quietly weaken it.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use crate::peer::PeerId;

/// Where a peer is in its lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerState {
    Disconnected,
    Connecting,
    Handshaking,
    /// Mutually authenticated: its `PeerId` is proven by the TLS verifier.
    Identified,
    /// Identified and exchanging application traffic.
    Active,
    Banned,
}

/// Misbehaviour the node penalises — the Huxplex penalties that sit beside GossipSub's own
/// scoring (wire spec §3: invalid signatures, cross-context replay attempts, spam).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Offence {
    /// Bytes that do not decode as the envelope the topic carries.
    Malformed,
    /// A well-formed envelope whose signature does not verify.
    InvalidSignature,
    /// A valid signature presented in the wrong context — another topic or network.
    CrossContextReplay,
    /// A DHT record that fails validation (bad signature, wrong key, wrong network).
    InvalidRecord,
    /// GossipSub's own scoring has graylisted the peer: it now drops everything the peer sends,
    /// so no further offence would ever reach this table. Bans outright — otherwise the peer is
    /// silenced but never disconnected, and keeps a connection slot for as long as it likes.
    GossipGraylisted,
}

impl Offence {
    /// Score delta. Calibrated so a handful of offences bans a peer, while a single corrupted
    /// message — which an honest peer behind a bad link could forward — does not.
    pub fn penalty(self) -> i32 {
        match self {
            Offence::Malformed => -20,
            Offence::InvalidSignature | Offence::CrossContextReplay | Offence::InvalidRecord => -30,
            Offence::GossipGraylisted => -100,
        }
    }

    /// Whether this offence bans regardless of the accumulated score.
    pub fn bans_outright(self) -> bool {
        matches!(self, Offence::GossipGraylisted)
    }
}

/// Thresholds and timings.
#[derive(Clone, Copy, Debug)]
pub struct PeerPolicy {
    /// A score at or below this bans the peer.
    pub ban_threshold: i32,
    pub ban_duration: Duration,
    /// First redial delay after a failed connection; doubles per consecutive failure.
    pub backoff_base: Duration,
    pub backoff_max: Duration,
    /// How long a disconnected peer's record is kept before it is forgotten.
    ///
    /// Without this the table grows by one entry per identity that ever connected, and identities
    /// are free: an ML-DSA keypair costs microseconds. Forgetting also forgets a negative score,
    /// which gives an offender nothing it could not get by generating a fresh identity.
    pub forget_after: Duration,
}

impl Default for PeerPolicy {
    fn default() -> Self {
        PeerPolicy {
            ban_threshold: -100,
            ban_duration: Duration::from_secs(600),
            backoff_base: Duration::from_millis(500),
            backoff_max: Duration::from_secs(60),
            forget_after: Duration::from_secs(600),
        }
    }
}

/// The outcome of a penalty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Tolerated {
        score: i32,
    },
    /// This offence crossed the threshold: the peer is banned from now.
    Banned {
        until: Instant,
    },
    /// The peer was banned already — an offence still in flight when the ban landed. The ban is
    /// neither extended nor re-announced.
    AlreadyBanned,
}

#[derive(Clone, Debug)]
struct Entry {
    state: PeerState,
    score: i32,
    failures: u32,
    retry_at: Option<Instant>,
    banned_until: Option<Instant>,
    /// When the peer last became `Disconnected`; what [`PeerTable::prune`] ages from.
    disconnected_at: Option<Instant>,
}

impl Default for Entry {
    fn default() -> Self {
        Entry {
            state: PeerState::Disconnected,
            score: 0,
            failures: 0,
            retry_at: None,
            banned_until: None,
            disconnected_at: None,
        }
    }
}

/// Every peer the node knows, and where each one is.
#[derive(Debug, Default)]
pub struct PeerTable {
    policy: PeerPolicy,
    peers: HashMap<PeerId, Entry>,
}

impl PeerTable {
    pub fn new(policy: PeerPolicy) -> Self {
        PeerTable {
            policy,
            peers: HashMap::new(),
        }
    }

    pub fn state(&self, peer: &PeerId) -> PeerState {
        self.peers
            .get(peer)
            .map_or(PeerState::Disconnected, |e| e.state)
    }

    pub fn score(&self, peer: &PeerId) -> i32 {
        self.peers.get(peer).map_or(0, |e| e.score)
    }

    /// Whether a dial may start now: not banned, not already connected, backoff elapsed.
    pub fn may_dial(&self, peer: &PeerId, now: Instant) -> bool {
        match self.peers.get(peer) {
            None => true,
            Some(e) => e.state == PeerState::Disconnected && e.retry_at.is_none_or(|t| now >= t),
        }
    }

    /// The gate on application traffic.
    pub fn may_process(&self, peer: &PeerId) -> bool {
        matches!(self.state(peer), PeerState::Identified | PeerState::Active)
    }

    pub fn dialing(&mut self, peer: PeerId) {
        self.advance(peer, PeerState::Connecting);
    }

    /// QUIC's handshake *is* the TLS handshake, so a connection attempt that has reached the
    /// peer is handshaking.
    pub fn handshaking(&mut self, peer: PeerId) {
        self.advance(peer, PeerState::Handshaking);
    }

    /// The transport authenticated the peer: TLS completed and its `PeerId` matched.
    pub fn identified(&mut self, peer: PeerId) {
        let entry = self.peers.entry(peer).or_default();
        if entry.state != PeerState::Banned {
            entry.state = PeerState::Identified;
            entry.failures = 0;
            entry.retry_at = None;
        }
    }

    /// First application traffic from an identified peer.
    pub fn active(&mut self, peer: PeerId) {
        if let Some(entry) = self.peers.get_mut(&peer) {
            if entry.state == PeerState::Identified {
                entry.state = PeerState::Active;
            }
        }
    }

    /// The last connection closed. `failed` marks a dial or handshake that never completed, which
    /// schedules an exponential backoff before the next attempt.
    pub fn disconnected(&mut self, peer: PeerId, failed: bool, now: Instant) {
        let policy = self.policy;
        let entry = self.peers.entry(peer).or_default();
        if entry.state == PeerState::Banned {
            return;
        }
        entry.state = PeerState::Disconnected;
        entry.disconnected_at = Some(now);
        if failed {
            entry.failures = entry.failures.saturating_add(1);
            let shift = entry.failures.saturating_sub(1).min(16);
            let delay = policy
                .backoff_base
                .saturating_mul(1 << shift)
                .min(policy.backoff_max);
            entry.retry_at = Some(now + delay);
        }
    }

    /// Records an offence. Crossing the ban threshold bans the peer until `now + ban_duration`.
    pub fn penalize(&mut self, peer: PeerId, offence: Offence, now: Instant) -> Verdict {
        let policy = self.policy;
        let entry = self.peers.entry(peer).or_default();
        if entry.state == PeerState::Banned {
            return Verdict::AlreadyBanned;
        }
        entry.score = entry.score.saturating_add(offence.penalty());
        if entry.score <= policy.ban_threshold || offence.bans_outright() {
            let until = now + policy.ban_duration;
            entry.state = PeerState::Banned;
            entry.banned_until = Some(until);
            Verdict::Banned { until }
        } else {
            Verdict::Tolerated { score: entry.score }
        }
    }

    pub fn is_banned(&self, peer: &PeerId) -> bool {
        self.state(peer) == PeerState::Banned
    }

    /// Lifts every ban that has expired by `now`, returning the peers released. A released peer
    /// starts again from a clean score — it is forgotten, which is the same thing.
    pub fn expire_bans(&mut self, now: Instant) -> Vec<PeerId> {
        let released: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(_, e)| {
                e.state == PeerState::Banned && e.banned_until.is_some_and(|t| now >= t)
            })
            .map(|(peer, _)| *peer)
            .collect();
        for peer in &released {
            self.peers.remove(peer);
        }
        released
    }

    /// Forgets every peer that has been disconnected for [`PeerPolicy::forget_after`] and has no
    /// backoff still pending. Connected and banned peers are never forgotten.
    pub fn prune(&mut self, now: Instant) {
        let forget_after = self.policy.forget_after;
        self.peers.retain(|_, e| {
            let idle = e.state == PeerState::Disconnected
                && e.retry_at.is_none_or(|t| now >= t)
                && e.disconnected_at.is_none_or(|t| now >= t + forget_after);
            !idle
        });
    }

    /// How many peers the table holds a record for.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    fn advance(&mut self, peer: PeerId, to: PeerState) {
        let entry = self.peers.entry(peer).or_default();
        if !matches!(
            entry.state,
            PeerState::Banned | PeerState::Identified | PeerState::Active
        ) {
            entry.state = to;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(b: u8) -> PeerId {
        PeerId { id: [b; 32] }
    }

    #[test]
    fn n8_messages_are_not_processed_before_identified() {
        let mut table = PeerTable::default();
        let p = peer(1);
        assert!(!table.may_process(&p), "unknown");
        table.dialing(p);
        assert!(!table.may_process(&p), "connecting");
        table.handshaking(p);
        assert!(!table.may_process(&p), "handshaking");
        table.identified(p);
        assert!(table.may_process(&p), "identified");
        table.active(p);
        assert!(table.may_process(&p), "active");
        assert_eq!(table.state(&p), PeerState::Active);
    }

    #[test]
    fn n8_failed_dials_back_off_exponentially_up_to_the_cap() {
        let policy = PeerPolicy {
            backoff_base: Duration::from_millis(100),
            backoff_max: Duration::from_millis(500),
            ..PeerPolicy::default()
        };
        let mut table = PeerTable::new(policy);
        let p = peer(2);
        let t0 = Instant::now();

        let mut expected = [100u64, 200, 400, 500, 500].into_iter();
        for _ in 0..5 {
            table.dialing(p);
            table.disconnected(p, true, t0);
            let delay = Duration::from_millis(expected.next().unwrap());
            assert!(!table.may_dial(&p, t0 + delay - Duration::from_millis(1)));
            assert!(table.may_dial(&p, t0 + delay));
        }

        // A successful connection resets the backoff.
        table.identified(p);
        table.disconnected(p, false, t0);
        assert!(table.may_dial(&p, t0));
    }

    #[test]
    fn n11_offences_accumulate_to_a_ban_and_the_ban_expires() {
        let mut table = PeerTable::default();
        let p = peer(3);
        table.identified(p);
        let now = Instant::now();

        assert_eq!(
            table.penalize(p, Offence::Malformed, now),
            Verdict::Tolerated { score: -20 }
        );
        for _ in 0..2 {
            assert!(matches!(
                table.penalize(p, Offence::InvalidSignature, now),
                Verdict::Tolerated { .. }
            ));
        }
        assert!(matches!(
            table.penalize(p, Offence::CrossContextReplay, now),
            Verdict::Banned { .. }
        ));
        assert!(table.is_banned(&p));
        assert!(
            !table.may_process(&p),
            "a banned peer's traffic is not processed"
        );
        assert!(!table.may_dial(&p, now));

        // A ban survives reconnection attempts and disconnection…
        table.identified(p);
        table.disconnected(p, false, now);
        assert!(table.is_banned(&p));

        // …and lifts at expiry, with a clean slate.
        let later = now + PeerPolicy::default().ban_duration;
        assert_eq!(table.expire_bans(later), vec![p]);
        assert_eq!(table.state(&p), PeerState::Disconnected);
        assert_eq!(table.score(&p), 0);
    }

    #[test]
    fn n11_an_offence_by_a_banned_peer_neither_extends_nor_repeats_the_ban() {
        let mut table = PeerTable::default();
        let p = peer(4);
        table.identified(p);
        let t0 = Instant::now();
        let until = loop {
            if let Verdict::Banned { until } = table.penalize(p, Offence::InvalidSignature, t0) {
                break until;
            }
        };
        // Messages already in flight when the ban landed are still reported…
        let later = t0 + Duration::from_secs(30);
        assert_eq!(
            table.penalize(p, Offence::InvalidSignature, later),
            Verdict::AlreadyBanned
        );
        // …but the ban still lifts when it was first set to.
        assert!(
            table
                .expire_bans(until - Duration::from_millis(1))
                .is_empty()
        );
        assert_eq!(table.expire_bans(until), vec![p]);
    }

    #[test]
    fn n8_disconnected_peers_are_forgotten_so_the_table_stays_bounded() {
        let policy = PeerPolicy {
            forget_after: Duration::from_secs(60),
            ..PeerPolicy::default()
        };
        let mut table = PeerTable::new(policy);
        let t0 = Instant::now();
        // A thousand throwaway identities, each connecting once and offending once.
        for i in 0..1000u32 {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            let p = PeerId { id };
            table.identified(p);
            table.penalize(p, Offence::Malformed, t0);
            table.disconnected(p, false, t0);
        }
        let connected = peer(5);
        table.identified(connected);
        let banned = peer(6);
        table.identified(banned);
        while !table.is_banned(&banned) {
            table.penalize(banned, Offence::InvalidRecord, t0);
        }

        table.prune(t0 + Duration::from_secs(59));
        assert_eq!(table.len(), 1002, "forgotten too early");
        table.prune(t0 + Duration::from_secs(60));
        assert_eq!(
            table.len(),
            2,
            "only the connected and the banned peer remain"
        );
        assert!(table.may_process(&connected));
        assert!(table.is_banned(&banned));
    }

    #[test]
    fn n11_a_gossipsub_graylisting_bans_whatever_the_score() {
        let mut table = PeerTable::new(PeerPolicy {
            ban_threshold: -1000,
            ..PeerPolicy::default()
        });
        let p = peer(7);
        table.identified(p);
        assert!(matches!(
            table.penalize(p, Offence::GossipGraylisted, Instant::now()),
            Verdict::Banned { .. }
        ));
    }
}
