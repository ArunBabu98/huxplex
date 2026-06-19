# ADR-0001: Reconcile readme vs. essay architecture

- Status: Accepted
- Date: 2026-06-19
- Deciders: Founding architect

## Context

Two authoritative-looking descriptions of Huxplex exist and disagree:
- The repository `readme.md`: token model `$HUX/$PLEX/$CRED`, "Proof of Sentience (PoSENT)",
  eUTXO ledger, Dilithium2 naming.
- The Medium vision essays: tokens `HUX/SVRGN/SNTNC`, "Hive-Mind governance", HRM resource
  machine, S-EUTXO sharding, Q-BFT, HuxVM, TCHAO, Work Visas, DIDs.

A blueprint needs one canonical model. Conflicts left unresolved calcify into bugs and confused
contributors.

## Options

- **A — Adopt the essays as canonical, map the readme onto them.** Essays are later + far more
  detailed; they describe the fuller architecture.
- **B — Adopt the readme as canonical.** It's the in-repo source of truth and is more modest/
  buildable, but much less complete.
- **C — Treat both as drafts and design fresh.** Maximum freedom, but discards real intent and
  the (excellent) existing crypto code that already aligns with the essays (DID=SHAKE-256(pk),
  context strings, BIP32 path).

## Decision

**Option A.** The Medium essays are the **evolved canonical architecture**; the readme is
preserved as the v1 *research-chain scope* and its concepts are mapped forward:

- Tokens: `$HUX/$PLEX/$CRED` → **`HUX(utility)/SVRGN(human gov)/SNTNC(agent merit)`** (note the
  HUX *meaning* changes from governance→utility; we adopt the essay meaning).
- "Proof of Sentience" → reframed as bounded, off-consensus merit/novelty (see ADR-0007).
- eUTXO → **HRM**, with eUTXO as a strict subset (see ADR-0003).
- The existing crypto/network code already matches the essays (context strings, PeerId, BIP32
  coin type 931931) — confirming the essays as the intended direction.

Also correct a factual error: the essays state ML-DSA-44 signature = 2,560 B; the **code-confirmed
signature size is 2,420 B** (2,560 B is the secret key). Code is authoritative on facts.

## Consequences

- ➕ One canonical vocabulary across all docs/code; ambiguity removed.
- ➕ Existing crypto code is validated as on-path, not throwaway.
- ➖ Naming migration needed if any testnet used the old `$HUX=governance` meaning.
- Follow-on: every doc/code reference must use the canonical column ([token-design](../06-tokenomics/token-design.md)).

## Links
- [token-design](../06-tokenomics/token-design.md), [00-executive-summary](../00-executive-summary.md)
</content>
