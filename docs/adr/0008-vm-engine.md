# ADR-0008: HuxVM — wasmi → wasmtime, behind a `Vm` trait

- Status: Accepted
- Date: 2026-06-19
- Deciders: Founding architect, execution

## Context

HuxVM must run resource-logic and agent programs **deterministically** (no FP/SIMD/threads/
syscalls, gas-metered, bounded loops). We need an engine that is determinism-friendly, has good
gas/fuel metering, and a viable performance path, while keeping the option to change engines.

## Options

- **A — `wasmtime`.** Mature, fast (Cranelift JIT), fuel/epoch metering, strong sandbox. *Cons*:
  must carefully disable nondeterministic features (FP/SIMD/threads); larger dependency.
- **B — `wasmi` (interpreter).** Tiny, simple, trivially deterministic, easy gas. *Cons*: slower.
- **C — Custom bytecode VM.** Full control, minimal surface. *Cons*: reinventing a VM; high risk.
- **D — RISC-V (PolkaVM-style).** Future-proof toolchain, good metering. *Cons*: newer, smaller
  ecosystem.

## Decision

**Start with `wasmi` (B) for the MVP, migrate to `wasmtime` (A) for Production**, both behind a
`Vm` trait so the engine is swappable (agility extends to infrastructure). Watch **RISC-V/PolkaVM
(D)** as a Future option.

Reasoning: correctness/determinism first — `wasmi`'s interpreter makes determinism trivial to
guarantee while the rest of the chain stabilizes. Switch to `wasmtime` (restricted profile: no FP/
SIMD/threads, fuel metering, module validation rejecting disallowed opcodes) once performance
matters. The `Vm` trait prevents lock-in.

## Consequences

- ➕ Determinism is easy to guarantee early; performance path exists later; no engine lock-in.
- ➕ Crypto exposed as gas-metered host functions works with either engine.
- ➖ Two integrations over time (wasmi then wasmtime); module-validation (opcode allowlist) is
  consensus-critical and must be identical across engines (differential-tested).
- Follow-on: restricted predicate language vs full WASM for `logic` (R-B10).

## Links
- [execution-engine](../02-architecture/execution-engine.md)
</content>
