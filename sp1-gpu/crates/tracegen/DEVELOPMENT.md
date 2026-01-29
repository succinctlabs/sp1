# Developing `sp1-gpu-tracegen`

This crate supports GPU trace generation. It exports two main items:

- `CudaTraceGenerator<F, A>`, which implements `TraceGenerator<F, A, TaskScope>`
  when `A: CudaTracegenAir<F>` (and some other conditions).
  This is used as the trace generator for `CudaProverComponents`.
- `CudaTracegenAir<F>`: a trait implemented by types that may support GPU trace generation.

The rest of this crate implements `CudaTracegenAir<KoalaBear>` for various types.

To implement the trait for an AIR, create a file in either the
`riscv` or `recursion` directory and update the implementation of the AIR enum
found in the directory's `mod.rs`. 

To actually implement and use CUDA code, you will have to do a few things:
- modify `crates/sys/build.rs` to tell `cbindgen` to generate the required types;
- write your (templated) CUDA kernels and nullary C++ functions that return function pointers
  to the (specialized) kernels as `KernelPtr`s;
- add `extern fn` declarations to `crates/sys/tracegen.rs`;
- add a trait to `crates/cuda/tracegen.rs` that exposes these kernels and implement it for `TaskScope`.

It is good practice to write a unit test or two to check that your GPU trace generation matches
SP1's default CPU trace generation.
