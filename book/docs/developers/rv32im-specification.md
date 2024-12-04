# RV32IM Specification

SP1 implements the RISC-V RV32IM instruction set with some implementation details that make it more suitable for proving.

- LW/SW memory access must be word aligned.
- LH/LHU/SH memory access must be half-word aligned.
- Memory access is only valid for addresses `0x20, 0x78000000`. Accessing addresses outside of this range will result in undefined behavior. The global heap allocator in `sp1_zkvm` will panic if memory exceeds this range.
- The ECALL instruction is used for system calls and precompiles. Only valid syscall IDs should be called, and only using the specific convention of loading the ID into register T0 and arguments into registers A0 and A1. If the arguments are addresses, they must be word-aligned. Failure to follow this convention can result in undefined behavior. Correct usages can be found in the `sp1_zkvm` and `sp1_lib` crates.
