# RV32IM Deviations

**SP1 does not conform exactly to the official RISC-V RV32IM specification.** Instead, it includes 
several minor modifications tailored to make it more suitable for use in proving systems. These 
deviations are outlined below:

- Addresses `0x0` to `0x20` are reserved for registers. Writing to these addresses will modify
  register state and cause divergent behavior from the RISC-V specification.
- Memory access is only valid for addresses `0x20, 0x78000000`. Writing to any other addresses
  will result in undefined behavior. The heap allocator is also constrained to these addresses.
- Memory access must be "aligned". The alignment is automatically enforced by all programs compiled
  through the official SP1 RISC-V toolchain.
    - LW/SW memory access must be word aligned. 
    - LH/LHU/SH memory access must be half-word aligned.
    - LW/SW memory access must be word aligned.
    - LH/LHU/SH memory access must be half-word aligned.
- The ECALL instruction is used for system calls and precompiles. Only valid syscall IDs should be called, and only using the specific convention of loading the ID into register T0 and arguments into registers A0 and A1. If the arguments are addresses, they must be word-aligned. Failure to follow this convention can result in undefined behavior. Correct usages can be found in the `sp1_zkvm` and `sp1_lib` crates.
- The instructions FENCE, WFI, MRET, and CSR related instructions will be categorized as not implemented,
  and hence not allowed by the SP1 zkvm.

## Security Considerations

While the deviations from the RISC-V specification could theoretically be exploited to cause 
divergent execution, such scenarios require a deliberately malicious program. The SP1 security 
model assumes that programs are honestly compiled, as malicious bytecode could otherwise exploit 
program execution and I/O.

These security concerns regarding divergent execution have been reviewed and discussed with external
security researchers, including rkm0959, Zellic, samczsun, and others.