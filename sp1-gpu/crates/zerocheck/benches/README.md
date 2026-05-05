# `zerocheck` benches

Times the `zerocheck` prover against one trace source per invocation. Source
selection is parsed from positional `--` args by
[`with_trace_source`](../../jagged_tracegen/src/test_utils.rs).

## Bench targets

| Cargo target | File |
| --- | --- |
| `zerocheck` | [`zerocheck.rs`](zerocheck.rs) |

## Commands

```bash
# Default: synthetic random trace at 2^25 field elements
cargo bench -p sp1-gpu-zerocheck --bench zerocheck

# Random with an explicit log-area
cargo bench -p sp1-gpu-zerocheck --bench zerocheck -- random:24

# Random sweep (one run per size)
cargo bench -p sp1-gpu-zerocheck --bench zerocheck -- random:22,24,26

# Trace from a JSON layout (path must end in .json)
cargo bench -p sp1-gpu-zerocheck --bench zerocheck -- /path/to/layout.json

# Trace from a real zkVM execution.
# Available programs: fibonacci, fibonacci_blake3, ed25519, keccak256, sha2,
# ssz_withdrawals, tendermint, groth16, groth16_blake3, plonk, plonk_blake3.
cargo bench -p sp1-gpu-zerocheck --bench zerocheck -- real/keccak256
```

## Disclaimer on synthetic data

`random` and JSON sources fill columns with uniformly random field elements,
which **do not satisfy any chip's AIR constraints**. The zerocheck *prover*
runs on any trace data — only verification cares about constraint
satisfaction — so timings are meaningful, but a proof on top of these traces
would not verify. Use `real/<program>` when you need end-to-end-valid inputs.

For random and JSON sources the helper synthesizes `cluster` as the full
chip set (alphabetical) and a zero-filled `public_values` of the right
length. That means synthetic-source timings reflect the largest-cluster
workload rather than the per-program workload `real/<name>` would produce.
