# `jagged_sumcheck` benches

Two Criterion benches live here. They share the source-selection machinery in
[`with_trace_source`](../../jagged_tracegen/src/test_utils.rs), but only
`jagged` actually consumes a trace — `hadamard` is size-only.

## Bench targets

| Cargo target | File | Source kinds |
| --- | --- | --- |
| `jagged` | [`jagged.rs`](jagged.rs) | random / JSON / real |
| `hadamard` | [`hadamard.rs`](hadamard.rs) | random only |

## `jagged` — `jagged_sumcheck`

```bash
# Default: synthetic random trace at 2^25 field elements
cargo bench -p sp1-gpu-jagged-sumcheck --bench jagged

# Random with an explicit log-area
cargo bench -p sp1-gpu-jagged-sumcheck --bench jagged -- random:24

# Random sweep (one run per size)
cargo bench -p sp1-gpu-jagged-sumcheck --bench jagged -- random:22,24,26

# Override the chip cluster the synthetic trace populates. Default is `core`
# (≈ base RISC-V); `all-chips` populates every chip on the machine.
cargo bench -p sp1-gpu-jagged-sumcheck --bench jagged -- random:24,cluster=all-chips

# Trace from a JSON layout (path must end in .json)
cargo bench -p sp1-gpu-jagged-sumcheck --bench jagged -- /path/to/layout.json

# Trace from a real zkVM execution.
# Available programs: fibonacci, fibonacci_blake3, ed25519, keccak256, sha2,
# ssz_withdrawals, tendermint, groth16, groth16_blake3, plonk, plonk_blake3.
cargo bench -p sp1-gpu-jagged-sumcheck --bench jagged -- real/keccak256
```

## `hadamard` — `simple_hadamard_sumcheck`

This bench operates on raw random `Felt` / `Ext` buffers, not on a chip
trace. It only accepts the `random` source.

```bash
# Default at 2^25
cargo bench -p sp1-gpu-jagged-sumcheck --bench hadamard

# Explicit log-length
cargo bench -p sp1-gpu-jagged-sumcheck --bench hadamard -- random:24

# Sweep across log-lengths
cargo bench -p sp1-gpu-jagged-sumcheck --bench hadamard -- random:22,24,26
```

JSON or `real/<program>` arguments will panic — the helpers don't synthesize
hadamard inputs. `cluster=` is accepted in the random spec for parser
uniformity but has no effect (hadamard doesn't iterate chips).

## Disclaimer on synthetic data

For `jagged`, the `random` and JSON sources fill columns with uniformly
random field elements, which **do not satisfy any chip's AIR constraints**.
Sumcheck timings are still meaningful, but a proof chain on top of these
traces would not verify. Use `real/<program>` when you need end-to-end-valid
inputs.

For `hadamard`, the bench passes `claim = 0` and timing is independent of
correctness, so the disclaimer is moot — the result is never a valid proof.
