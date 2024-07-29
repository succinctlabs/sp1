# RV32IM Implementation Details

SP1 implements the RISC-V RV32IM instruction set with some implementation details that make it more suitable for proving.

- LW/SW memory access must be word aligned.
- LH/LHU/SH memory access must be half-word aligned.
- Memory access is only valid for addresses [0x20, 0x78000000]. Accessing outside this range will result in undefined behavior.
- ECALL instruction is used for system calls and precompiles. Only valid syscall IDs should be called. For precompiles that take in a memory address, it should be word-aligned.
