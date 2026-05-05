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

# Override the chip cluster the synthetic trace populates. Default is `core`
# (≈ base RISC-V, no extensions or precompiles); `all-chips` populates every
# chip on the machine — a worst-case stress test, not comparable to any real
# shard. `cluster=` can be combined with size sweeps.
cargo bench -p sp1-gpu-zerocheck --bench zerocheck -- random:24,cluster=all-chips
cargo bench -p sp1-gpu-zerocheck --bench zerocheck -- random:22,24,26,cluster=all-chips

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

For random the helper synthesizes `cluster` from the [`ChipCluster`]
choice (default: `core`, ≈ base RISC-V) and a zero-filled `public_values`
of the right length. JSON sources take their chip set from the layout file.
The cluster choice matters: zerocheck does per-chip work, so spreading the
same total area across more chips (e.g. `cluster=all-chips`) shifts the
workload from per-row work toward per-chip constants and can make the bench
look slower without doing more "real" computation. Default `core` is the
closest synthetic analogue to the cluster a fibonacci-shaped program lands
in; use `real/<name>` for an exact per-program comparison.
