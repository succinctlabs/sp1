# `commit` benches

Times `sp1_gpu_commit::commit_multilinears` against one trace source per
invocation. Source selection is parsed from positional `--` args by
[`with_trace_source`](../../jagged_tracegen/src/test_utils.rs); all benches
in this folder accept the same forms.

## Bench targets

| Cargo target | File |
| --- | --- |
| `commit` | [`commit.rs`](commit.rs) |

## Commands

```bash
# Default: synthetic random trace at 2^25 field elements
cargo bench -p sp1-gpu-commit --bench commit

# Random with an explicit log-area
cargo bench -p sp1-gpu-commit --bench commit -- random:24

# Random sweep across multiple log-areas (one bench run per size)
cargo bench -p sp1-gpu-commit --bench commit -- random:22,24,26

# Override the chip cluster the synthetic trace populates. Default is `core`
# (≈ base RISC-V); `all-chips` populates every chip on the machine.
cargo bench -p sp1-gpu-commit --bench commit -- random:24,cluster=all-chips

# Trace built from a JSON layout file (path must end in .json)
cargo bench -p sp1-gpu-commit --bench commit -- /path/to/layout.json

# Trace from an actual zkVM execution of a sample program.
# Available programs: fibonacci, fibonacci_blake3, ed25519, keccak256, sha2,
# ssz_withdrawals, tendermint, groth16, groth16_blake3, plonk, plonk_blake3.
cargo bench -p sp1-gpu-commit --bench commit -- real/keccak256
```

## Disclaimer on synthetic data

`random` and JSON sources fill columns with uniformly random field elements,
which **do not satisfy any chip's AIR constraints**. The commit step itself
doesn't check constraints, so timings are meaningful, but a proof chain built
on top of these traces would not verify. Use `real/<program>` when you need
end-to-end-valid inputs.
