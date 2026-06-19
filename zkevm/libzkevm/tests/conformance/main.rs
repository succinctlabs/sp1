//! EVM-precompile conformance tests.
//!
//! Runs the FULL official vector suites — go-ethereum's
//! `core/vm/testdata/precompiles` (including the `fail-*` rejection
//! vectors) and Wycheproof ECDSA — against the C-ABI accelerator
//! functions, on the host (software fallback paths of the same patched
//! crates that route to syscalls at `target_os = "zkvm"`).
//!
//! Vector provenance: see `tests/data/README.md`. Vectors are consumed
//! wholesale, never sampled — the adversarial tail is the point.
//!
//! The `support::wire` module is the EVM-wire-format ↔ C-ABI glue an
//! EVM client integrating this SDK needs (EIP-2537 64-byte padded Fp,
//! `c0 || c1` Fp2 order, all-zeros infinity — versus the ABI's 48-byte
//! Fp, `c1 || c0`, `0x40` flag-bit infinity).

mod bls;
mod evm;
mod support;
mod wycheproof;

/// `ZKVM_EOK` per `zkvm_accelerators.h` (the Rust crate keeps the
/// constants `pub(crate)`; the C enum pins them to 0 / -1).
pub const EOK: i32 = 0;
/// `ZKVM_EFAIL` per `zkvm_accelerators.h`.
pub const EFAIL: i32 = -1;
