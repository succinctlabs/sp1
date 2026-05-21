# Cost artifacts

`rv64im_costs.json` is parsed by `rv64im_costs()` in `crates/core/executor/src/utils.rs`
(and two other loaders in the same crate). Format: a flat `{ "<RiscvAirId-name>": <usize> }`
map. The parser does not tolerate comments or extra keys — every key must round-trip
through `RiscvAirId::from_str`, and every value must be a non-negative integer.
