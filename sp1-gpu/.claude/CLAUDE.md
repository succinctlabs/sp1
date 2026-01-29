# SP1-GPU Guide

# Rust best practices
Make sure to follow Rust best practices when working with this repository. This includes using `cargo fmt` for formatting and `cargo clippy` for linting.

## Crates Overview
GPU-accelerated cryptographic proving system for SP1 (Succinct's zkVM). It provides CUDA implementations of core proving operations to achieve significant speedups over CPU-only proving.

### Functionality
- **GPU-accelerated proving**: Implements CUDA kernels for computationally intensive operations (NTT, Poseidon2 hashing, Merkle trees, sumcheck, etc.)
- **SP1 integration**: Works with the SP1 zkVM prover stack via the `slop-*` and `sp1-*` crate dependencies
- **FFI bridge**: Exposes CUDA functionality to Rust through the `sp1-gpu-sys` crate

### Key Dependencies
- **slop-*** crates: Core proving primitives from `sp1-wip` (multilinear_v6 branch)
- **sp1-*** crates: SP1 zkVM machine definitions and executors
- **sppark**: External CUDA library for NTT kernels and field arithmetic (Koala Bear field)

## Directory Structure

```
sp1-gpu/
├── include/           # CUDA headers (.cuh) organized by module
│   ├── algebra/       # Field arithmetic operations
│   ├── basefold/      # Basefold polynomial commitment
│   ├── challenger/    # Fiat-Shamir challenger
│   ├── fields/        # Field type definitions (kb31_t, bn254_t, etc.)
│   ├── merkle_tree/   # Merkle tree hashing
│   ├── ntt/           # Number Theoretic Transform
│   ├── poseidon2/     # Poseidon2 hash function
│   ├── tracegen/      # Trace generation for jagged/stacked traces
│   └── ...            # Other modules
├── lib/               # CUDA sources (.cu) organized by module
│   └── <module>/      # Each has CMakeLists.txt + source files
├── sppark/            # External: NTT kernels and field arithmetic (DO NOT MODIFY)
├── crates/            # Rust crates
│   ├── sys/           # FFI bindings, CUDA build orchestration
│   ├── cuda/          # High-level Rust wrappers for CUDA ops
│   ├── shard_prover/  # Main shard prover implementation
│   ├── merkle_tree/   # Merkle tree prover (CUDA-accelerated)
│   ├── jagged_tracegen/ # GPU trace generation
│   ├── perf/          # Performance benchmarks and testing
│   └── ...            # Other crates
├── CMakeLists.txt     # Root CMake configuration for CUDA build
└── target/            # Build artifacts
    └── cuda-build/    # CUDA compilation output (libsys-cuda.a)
```

## Build System

### How It Works
1. **Cargo** triggers build via `crates/sys/build.rs`
2. **build.rs** generates cbindgen headers, then invokes CMake
3. **CMake** compiles all CUDA modules into object libraries
4. **Device linking** combines objects into `libsys-cuda.a`
5. **Cargo** links the static library into Rust binaries

### Key Files
| File | Purpose |
|------|---------|
| `CMakeLists.txt` | Root CUDA build configuration |
| `lib/<module>/CMakeLists.txt` | Per-module CUDA source lists |
| `crates/sys/CMakeLists.txt` | Entry point from Cargo (calls root CMake) |
| `crates/sys/build.rs` | Orchestrates cbindgen + CMake + linking |

### Build Commands
```bash
cargo build --release         # Standard release build
cargo build --profile lto     # With link-time optimization
cargo build                   # Debug build (still uses -O3 for CUDA)
```

### Environment Variables
| Variable | Purpose |
|----------|---------|
| `CUDA_ARCHS` | Override GPU architectures (e.g., "89" for RTX 4090 only) |
| `PROFILE_DEBUG_DATA=true` | Enable CUDA debug symbols (-G flag) |

## Crate Overview

### Core Crates
| Crate | Purpose |
|-------|---------|
| **sp1-gpu-sys** | FFI bindings, CUDA compilation, kernel function exports |
| **sp1-gpu-cudart** | High-level Rust API for GPU operations (TaskScope, memory management) |
| **sp1-gpu-shard-prover** | Main shard proving logic |
| **sp1-gpu-merkle-tree** | GPU-accelerated Merkle tree commitment |
| **sp1-gpu-jagged-tracegen** | GPU trace generation for jagged/stacked traces |
| **sp1-gpu-perf** | Benchmarks and performance testing |
| **sp1-gpu-challenger** | Fiat-Shamir challenger implementation |
| **sp1-gpu-basefold** | Basefold polynomial commitment |
| **sp1-gpu-zerocheck** | Zerocheck protocol |
| **sp1-gpu-logup-gkr** | LogUp-GKR protocol |

## CUDA Modules

The CUDA code is organized into modules under `include/` (headers) and `lib/` (sources):

| Module | Purpose |
|--------|---------|
| `algebra` | Field arithmetic operations |
| `basefold` | Basefold commitment kernels |
| `challenger` | Challenger state management |
| `fields` | Field type definitions (Koala Bear, BN254) |
| `jagged_assist` | Helper kernels for jagged traces |
| `jagged_sumcheck` | Sumcheck over jagged polynomials |
| `logup_gkr` | LogUp-GKR protocol kernels |
| `merkle_tree` | Merkle tree leaf hashing and compression |
| `mle` | Multilinear extension operations |
| `ntt` | Number Theoretic Transform (via sppark) |
| `poseidon2` | Poseidon2 hash (Koala Bear 16-width, BN254 3-width) |
| `runtime` | CUDA runtime utilities, error handling |
| `scan` | Parallel prefix scan |
| `sum_and_reduce` | Reduction kernels |
| `tracegen` | GPU trace generation |
| `transpose` | Matrix transpose operations |
| `zerocheck` | Zerocheck protocol kernels |

## Running Benchmarks

### Node Benchmark (Full Proving)
```bash
# Core mode (fastest, no recursion)
RUST_LOG="info" cargo run --release -p sp1-gpu-perf --bin node -- \
    --program v6/fibonacci-200m --mode core

# Compressed mode (with recursion)
RUST_LOG="info" cargo run --release -p sp1-gpu-perf --bin node -- \
    --program v6/fibonacci-200m --mode compressed
```

### Available Programs
Programs are in the `v6/` directory convention. Common ones:
- `fibonacci-20m`, `fibonacci-200m` - Fibonacci sequence computation
- Check `sp1-gpu-perf` for available benchmark programs

## Development Notes

### Adding a New CUDA Module
1. Create `include/<module>/` with header files
2. Create `lib/<module>/` with source files
3. Add `lib/<module>/CMakeLists.txt`:
   ```cmake
   add_library(<module>_objs OBJECT
       file1.cu
       file2.cu
   )
   ```
4. Add `add_subdirectory(lib/<module>)` to root `CMakeLists.txt`
5. Add `$<TARGET_OBJECTS:<module>_objs>` to `ALL_CUDA_OBJECTS`

### Common Issues
| Issue | Solution |
|-------|----------|
| "nvcc not found" | Install CUDA toolkit, ensure `nvcc` is in PATH |
| Rebuild every time | Check `build.rs` rerun-if-changed paths are valid |
| Device linking errors | Ensure `-rdc=true` flag and `CUDA_RESOLVE_DEVICE_SYMBOLS ON` |
| Missing symbols | Check library link order in `build.rs` |

### Code Quality
Before committing, run:
```bash
cargo +stable fmt --all -- --check
cargo +stable clippy -- -D warnings -A incomplete-features
```

## Architecture Requirements

- **CUDA 12.0+** required
- Supported GPU architectures:
  - sm_80: Ampere (A100, RTX 30xx)
  - sm_86: Ampere consumer
  - sm_89: Ada Lovelace (RTX 40xx)
  - sm_90: Hopper (H100)
  - sm_100+: Blackwell and newer (CUDA 12.8+)

## Profiling

Use NVIDIA tools for GPU profiling:
```bash
# Nsight Systems (timeline)
nsys profile cargo run --release -p sp1-gpu-perf --bin node -- --program v6/fibonacci-20m --mode core

# Nsight Compute (kernel analysis)
ncu --set full cargo run --release -p sp1-gpu-perf --bin node -- --program v6/fibonacci-20m --mode core
```

The `-lineinfo` CUDA flag is always enabled for profiler source correlation.
