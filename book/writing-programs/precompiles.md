# Precompiles

Precompiles are built into the SP1 zkVM and accelerate commonly used operations such as elliptic curve arithmetic and hashing. Under the hood, precompiles are implemented as custom STARK tables dedicated to proving one or few operations. **They typically improve the performance
of executing expensive operations in SP1 by a few orders of magnitude.**

Inside the zkVM, precompiles are exposed as system calls executed through the `ecall` RISC-V instruction.
Each precompile has a unique system call number and implements an interface for the computation.

SP1 also has been designed specifically to make it easy for external contributors to create and extend the zkVM with their own precompiles.
To learn more about this, you can look at implementations of existing precompiles in the [precompiles](https://github.com/succinctlabs/sp1/tree/main/core/src/syscall/precompiles) folder. More documentation on this will be coming soon.

**To use precompiles, we typically recommend you interact with them through [patches](./patched-crates.md), which are crates modified
to use these precompiles under the hood, without requiring you to call system calls directly.**

## Specification

If you are an advanced user you can interact with the precompiles directly using external system calls.

Here is a list of all available system calls & precompiles.

```rust,noplayground
{{#include ../../zkvm/lib/src/lib.rs}}
```