# VEIL — Verifiable Encapsulation of Interactive proofs with Low overhead

> **Warning:** This is experimental, proof-of-concept code. It has not been audited and should not be used in production.

## Overview

VEIL is a zero-knowledge wrapper for multilinear interactive oracle proofs (MIOPs). It takes an existing IOP (such as sumcheck) and adds zero-knowledge with low overhead, without modifying the underlying protocol. See the paper in [paper/veil.pdf](paper/veil.pdf) for details.

The key idea: queries to multilinear oracles are dealt with using a zk-PCS. The prover in addition masks all non-oracle transcript values with random "veil" elements, then proves via a R1CS-ish constraint system that the masked values satisfy the original protocol's checks. The verifier never sees the raw transcript — only the masked version plus a proof of correctness.

## Modules

- **`compiler`** — Public trait interface. `ReadingCtx` reads values and oracles from the transcript, `SendingCtx` sends values from the prover, and `ConstraintCtx` builds constraints (`assert_zero`, `assert_mle_eval`). User code is generic over these traits, so the same functions work for mask counting, proving, and verifying.
- **`protocols`** — Protocol building blocks on top of the compiler traits: `SumcheckParam` and `ZerocheckParam`.
- **`zk`** — ZK proving/verification engine. `ZkProverCtx` and `ZkVerifierCtx` implement the compiler traits.

## Usage

To convert an existing IOP into a ZK protocol using VEIL:

1. **Identify the transcript** — every value the prover sends, every oracle commitment, and every verifier challenge. Partition the field values into a sequence of messages.
2. **Write a generic `read` function** over `ReadingCtx` — this replaces the verifier's transcript parsing and Fiat-Shamir reconstruction. Each message maps to `ctx.read_one()` (single element) or `ctx.read_next(n)` (multi-element). Oracle commitments become `ctx.read_oracle(num_encoding_variables, log_num_polynomials)`, and challenges become `ctx.sample()` or `ctx.sample_point(dim)`. All read values are automatically absorbed into the Fiat-Shamir transcript.
3. **Write a generic `build_constraints` function** over `ConstraintCtx` — this encodes the verifier's checks. The `read_*` calls from step 2 return abstract `Expr` values that support arithmetic (`+`, `*`, etc.), so you can build polynomial expressions from them. Each verifier check becomes `ctx.assert_zero(expr)` or `ctx.assert_mle_eval(oracle, point, eval)`.
4. **Write the prover** — adapt the original prover so that it calls `ctx.send_value(v)` or `ctx.send_values(&[v1, v2, ...])` (matching the message partition from step 1) and `ctx.commit_mle(...)` for oracles. Sent values are also automatically absorbed into the Fiat-Shamir transcript.
5. **Putting it together**:
   - **Mask counting**: `compute_mask_length::<GC, _>(read_all, |data, ctx| build_all_constraints(data, ctx))` — dry-run to determine the number of masks needed.
   - **PCS setup** (if using oracles): `initialize_zk_prover_and_verifier(num_commitments, num_encoding_variables)` returns a `(pcs_prover, pcs_verifier)` pair.
   - **Prover**: initialize with `ZkProverCtx::initialize_with_pcs(mask_length, pcs_prover, &mut rng)` (or `initialize_with_pcs_only_lin(...)` if no multiplicative constraints; or `initialize_without_pcs(...)` / `initialize_without_pcs_only_lin(...)` if no PCS). Run the prover logic (step 4), call `build_all_constraints(data, &mut prover_ctx)`, then `prover_ctx.prove(&mut rng)`.
   - **Verifier**: `let mut verifier_ctx = ZkVerifierCtx::init(proof, Some(pcs_verifier))` (or `None`). Then `let data = read_all(&mut verifier_ctx)`, `build_all_constraints(data, &mut verifier_ctx)`, `verifier_ctx.verify()`.

### Examples

- [`examples/root.rs`](examples/root.rs) — ZK proof of knowledge of a polynomial root (pure constraints, no PCS)
- [`examples/mle_eval.rs`](examples/mle_eval.rs) — ZK proof of an MLE evaluation with PCS commitment
- [`examples/zerocheck.rs`](examples/zerocheck.rs) — Zerocheck protocol proving that the pointwise product of two committed MLEs equals a third (sumcheck + PCS + polynomial constraints)

## Building and Testing

```bash
# Build
cargo build -p slop-veil

# Run tests
cargo test --release -p slop-veil

# Run examples
cargo run --release -p slop-veil --example root
cargo run --release -p slop-veil --example mle_eval
cargo run --release -p slop-veil --example zerocheck

# Build with constraint debugging (prints constraint locations on failure)
RUSTFLAGS="--cfg sp1_debug_constraints" cargo test --release -p slop-veil

# Run benchmarks (ZK overhead vs standard sumcheck)
cargo test --release -p slop-veil --test benchmarking_tests -- --nocapture
```

## License

See the repository root for license information.
