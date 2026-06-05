# `shard_prover` benches

Times `CudaShardProver::prove_trusted_evaluations` against one trace source
per invocation. Source selection is parsed from positional `--` args by
[`with_trace_source`](../../jagged_tracegen/src/test_utils.rs).

## Bench targets

| Cargo target | File |
| --- | --- |
| `prove_trusted_evaluations` | [`prove_trusted_evaluations.rs`](prove_trusted_evaluations.rs) |

## Commands

```bash
# Default: synthetic random trace at 2^25 field elements
cargo bench -p sp1-gpu-shard-prover --bench prove_trusted_evaluations

# Random with an explicit log-area
cargo bench -p sp1-gpu-shard-prover --bench prove_trusted_evaluations -- random:24

# Random sweep (one run per size)
cargo bench -p sp1-gpu-shard-prover --bench prove_trusted_evaluations -- random:22,24,26

# Override the chip cluster the synthetic trace populates. Default is `core`
# (≈ base RISC-V); `all-chips` populates every chip on the machine.
cargo bench -p sp1-gpu-shard-prover --bench prove_trusted_evaluations -- random:24,cluster=all-chips

# Trace from a JSON layout (path must end in .json)
cargo bench -p sp1-gpu-shard-prover --bench prove_trusted_evaluations -- /path/to/layout.json

# Trace from a real zkVM execution.
# Available programs: fibonacci, fibonacci_blake3, ed25519, keccak256, sha2,
# ssz_withdrawals, tendermint, groth16, groth16_blake3, plonk, plonk_blake3.
cargo bench -p sp1-gpu-shard-prover --bench prove_trusted_evaluations -- real/keccak256

# Synthetic many-chip stress (defaults: 200 chips × widths in [50,10000] × height 32).
# Stresses the column-count dimension without forcing a huge total trace area.
cargo bench -p sp1-gpu-shard-prover --bench prove_trusted_evaluations -- synth

# Synth with overrides (any subset of chips=N, cols=LO:HI, height=N).
cargo bench -p sp1-gpu-shard-prover --bench prove_trusted_evaluations -- synth:chips=500,cols=100:5000,height=32
```

## Disclaimer on synthetic data

`random` and JSON sources fill columns with uniformly random field elements,
which **do not satisfy any chip's AIR constraints**. `prove_trusted_evaluations`
itself doesn't validate constraint satisfaction — the prover happily runs on
any trace shape — so timings are meaningful, but the resulting proofs would
not verify. Use `real/<program>` when you need end-to-end-valid inputs.
