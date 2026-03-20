# SP1 Project Guidelines

## Repository Structure

- `crates/` - SP1 core crates (hypercube, prover, sdk, recursion, etc.)
- `slop/crates/` - Low-level cryptographic primitives (algebra, tensor, multilinear, merkle-tree, sumcheck, basefold, jagged, whir, etc.)
- `examples/` - Example programs using SP1

## Build & Test Commands

```bash
# Build a specific crate
cargo build -p <crate-name>

# Test a specific crate
cargo test --release -p <crate-name>

# E2E prover test (comprehensive, takes ~15 min)
cargo test --release -p sp1-prover test_e2e_node

# Check formatting. Run this and fix errors before handing control back to the user.
cargo fmt --all -- --check

# Run clippy. Run this and fix errors before handing control back to the user.
cargo clippy -p <crate-name> --all-targets --all-features -- -D warnings -A incomplete-features
```

## Code Style Preferences

### Dependency Management
- Remove unused dependencies after refactoring
- Check both `[dependencies]` and `[dev-dependencies]` sections
- Prefer minimal dependencies - don't keep things "just in case"

### Traits and Generics
- Keep data structures (Tensor, Mle, Buffer) generic over backend for potential GPU support
- Use type aliases to reduce clippy type complexity warnings
- Prefer concrete implementations over overly abstract traits when simplicity helps

### API & Naming
- Name methods after what they mean in the protocol, not the mechanical action (e.g., `send_value` not `write` — the prover *sends* to the verifier in an interactive protocol)
- If you find yourself writing runtime `match` arms that panic on "impossible" variants, the type system is wrong — introduce a new associated type or narrower type instead
- Public wrappers around inner types should expose a clean interface via public traits; keep inner implementation details behind `pub(crate)` boundaries
- When adding associated types to traits, think about what bounds downstream default implementations need (e.g., `Expr: Algebra<Challenge>` is needed if `poly_eval` multiplies expressions by challenges)

### Testing
- Run tests after each significant change to catch issues early
- Use `cargo test -p <crate>` to test individual crates during development
- Run fmt and clippy before considering work complete

## Key Crates Reference

### slop-merkle-tree
- `TensorCsProver` - Tensor commitment scheme prover trait
- `ComputeTcsOpenings` - Compute openings at indices
- `FieldMerkleTreeProver` - Concrete Poseidon2-based implementation

### sp1-hypercube
- `ShardProver` - Core shard proving logic
- `SimpleProver` - High-level prover interface
- `ShardVerifier` - Verification logic

### slop-jagged
- `JaggedProver` - Prover for jagged (variable-size) polynomials
- `JaggedPcsVerifier` - Verifier for jagged PCS

### slop-multilinear
- `Mle` - Multilinear extension representation
- `PaddedMle` - Padded MLE for uniform sizing
- `Point` - Evaluation point

## Workflow Tips

1. **Build incrementally** - Test individual crates before full builds
2. **Check downstream** - Changes to slop crates affect sp1 crates
3. **Verify with tests** - Run relevant tests after changes
4. **Clean up** - Remove unused code/dependencies, run fmt/clippy
