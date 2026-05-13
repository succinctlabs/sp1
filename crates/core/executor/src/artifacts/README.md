# Cost artifacts

`rv64im_costs.json` is parsed by `rv64im_costs()` in `crates/core/executor/src/utils.rs`
(and two other loaders in the same crate). Format: a flat `{ "<RiscvAirId-name>": <usize> }`
map. The parser does not tolerate comments or extra keys — every key must round-trip
through `RiscvAirId::from_str`, and every value must be a non-negative integer.

## Placeholder values

The following entries are placeholders that need to be replaced once the real chip
layout is implemented (cost = column count × constraint degree):

- `Secp256k1MulAssign` (value mirrors `Secp256k1AddAssign`)
- `Secp256k1MulAssignUser` (value mirrors `Secp256k1AddAssignUser`)

They exist solely so that `cost_and_height_per_syscall` in `utils.rs` doesn't panic on a
missing-key lookup when the `SECP256K1_MUL` syscall fires in `--mode node` / `--mode gas`.
