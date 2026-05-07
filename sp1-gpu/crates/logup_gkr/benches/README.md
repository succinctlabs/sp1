# `logup_gkr` benches

One Criterion bench lives here, plus one legacy harness reachable as a Cargo
example (not a bench — see below). The Criterion bench shares the
source-selection machinery in
[`with_trace_source`](../../jagged_tracegen/src/test_utils.rs); the legacy
harness predates that framework and reads its own JSON workload file.

## Bench targets

| Cargo target | File | Purpose |
| --- | --- | --- |
| `gkr` | [`gkr.rs`](gkr.rs) | Two named groups (`populate_circuit`, `prove`), framework-driven. |

The legacy layer-by-layer harness (loads `layer_workloads.json`, prints
per-layer timings) lives at [`../examples/legacy_bench.rs`](../examples/legacy_bench.rs).
It's an `[[example]]`, not a `[[bench]]`.

## `gkr` — `populate_circuit` and `prove`

The file registers two named bench groups that both run off the same
`FullKind` trace source:

- `populate_circuit` times [`generate_gkr_circuit`](../src/lib.rs) — building
  the layer stack from the trace.
- `prove` times [`prove_gkr_circuit`](../src/lib.rs) — running the
  layer-by-layer sumcheck loop and Fiat-Shamir.

```bash
# Default: synthetic random trace at 2^25 field elements, core cluster
cargo bench -p sp1-gpu-logup-gkr --bench gkr

# Random with an explicit log-area
cargo bench -p sp1-gpu-logup-gkr --bench gkr -- random:24

# Random sweep (one run per size, both groups)
cargo bench -p sp1-gpu-logup-gkr --bench gkr -- random:22,24,26

# Override the chip cluster the synthetic trace populates. Default is `core`
# (≈ base RISC-V); `all-chips` populates every chip on the machine.
cargo bench -p sp1-gpu-logup-gkr --bench gkr -- random:24,cluster=all-chips

# Trace from a JSON layout (path must end in .json)
cargo bench -p sp1-gpu-logup-gkr --bench gkr -- /path/to/layout.json

# Trace from a real zkVM execution.
# Available programs: fibonacci, fibonacci_blake3, ed25519, keccak256, sha2,
# ssz_withdrawals, tendermint, groth16, groth16_blake3, plonk, plonk_blake3.
cargo bench -p sp1-gpu-logup-gkr --bench gkr -- real/keccak256

# Run only one of the two groups (Criterion filter syntax).
cargo bench -p sp1-gpu-logup-gkr --bench gkr -- populate_circuit
cargo bench -p sp1-gpu-logup-gkr --bench gkr -- prove
```

## `legacy_bench` example — original layer-by-layer harness

This is the pre-framework harness. It loads
`crates/logup_gkr/layer_workloads.json` (curated per-layer
`interaction_row_counts` and `num_row_variables`) and reports per-layer
trace-gen / proof-gen timings. Useful when you want to compare against an
exact production workload shape that the framework can't reconstruct from a
trace MLE alone.

```bash
# Run the layer-by-layer harness. Reads layer_workloads.json from CWD —
# invoke from the workspace root.
cargo run --release -p sp1-gpu-logup-gkr --example legacy_bench
```

## Disclaimer on synthetic data

For `gkr`, `random` and JSON sources fill columns with uniformly random
field elements, which **do not satisfy any chip's AIR constraints**. GKR's
populate + prove steps don't validate constraints — only verification does
— so timings are meaningful, but a proof on top of these traces would not
verify. Use `real/<program>` when you need end-to-end-valid inputs.

For `random` sources the helper synthesizes `cluster` from the
[`ChipCluster`] choice (default: `core`, ≈ base RISC-V) and a zero-filled
`public_values` of the right length. The cluster choice matters for GKR:
it determines the total number of interactions and per-chip row counts,
which directly drives the size of every layer in the circuit. Default
`core` is the closest synthetic analogue to the cluster a fibonacci-shaped
program lands in; use `real/<name>` for an exact per-program comparison.
