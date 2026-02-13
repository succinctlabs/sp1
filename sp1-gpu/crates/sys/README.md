# sp1-gpu-sys

FFI bindings and CUDA build system for SP1-GPU.

Provides the low-level FFI bindings to CUDA libraries and manages the build process for CUDA kernels. This crate handles cbindgen header generation and CMake-based CUDA compilation.

## Build Process

1. Cargo triggers `build.rs`
2. cbindgen generates C headers from Rust types
3. CMake compiles CUDA modules into object libraries
4. Device linking produces `libsys-cuda.a`
5. Cargo links the static library into Rust binaries

---

Part of [SP1-GPU](https://github.com/succinctlabs/sp1/tree/dev/sp1-gpu), the GPU-accelerated prover for SP1.
