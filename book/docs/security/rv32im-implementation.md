
# RV32IM Standards Compliance

SP1 is a specialized implementation of the RISC-V RV32IM standard and aligns with the fundamental philosophy of RISC-V, which emphasizes customization and flexibility over rigid adherence to a fixed set of instructions.

Notably, RISC-V is designed as a modular ISA framework that encourages implementers to adapt and specialize its base specifications to meet unique application requirements. SP1, which is tailored for zero-knowledge proving workloads, embodies this philosophy by introducing minor adjustments that enhance proving efficiency while adhering to the core RV32IM requirements. These design choices reflect the intent of RISC-V to act as a “skeleton” rather than an immutable standard as outlined in the [RISC-V specification](https://riscv.org/wp-content/uploads/2017/05/riscv-spec-v2.2.pdf): 

> RISC-V has been designed to support extensive customization and specialization. The base integer ISA can be extended with one or more optional instruction-set extensions, but the base integer instructions cannot be redefined. ... The base is carefully restricted to a minimal set of instructions sufficient to provide a reasonable target for compilers, assemblers, linkers, and operating systems (with additional supervisor-level operations), and so provides a convenient ISA and software toolchain “skeleton” around which more customized processor ISAs can be built.

SP1’s primary customizations, such as requiring aligned memory access and reserving specific memory regions, are implementation details optimized for zkVMs. These modifications are consistent with RISC-V’s allowance for customization, as the specification explicitly permits implementers to define legal address spaces and undefined behaviors. 

*This topic was thoroughly investigated by external auditors, including rkm0959, Zellic, samczsun, and others. The audit report by Zellic on this subject can be found [here](https://github.com/succinctlabs/sp1/tree/dev/audits).*

## Implementation Details

In this section, we outline the specific customizations made to SP1's implementation of the RISC-V RV32IM standard to simplify constraints and improve proving time.

### Reserved Memory Regions

SP1 reserves the following memory regions:
- `0x0` to `0x1F` inclusive are reserved for registers. Writing to these addresses will modify
  register state and cause undefined behavior. SP1's AIRs also constrain that memory opcodes do not access these addresses.
- `0x20` to `0x78000000` inclusive are reserved for the heap allocator. Writing to addresses outside this region will
  cause undefined behavior.

The RISC-V standard permits implementers to define which portions of the address space are legal to access and does not prohibit the specification of undefined behavior. SP1 adheres to this flexibility by defining valid memory regions from `0x20` to `0x78000000`, with accesses outside this range constituting undefined behavior. This design choice aligns with common practices in hardware platforms, where reserved or invalid memory regions serve specific purposes, such as [DMA](https://en.wikipedia.org/wiki/Direct_memory_access) or [MMIO](https://en.wikipedia.org/wiki/Memory-mapped_I/O_and_port-mapped_I/O), and accessing them can result in unpredictable behavior. Compared to real-world systems like x86 and ARM, SP1's memory map is neither that unusual nor complex.

In practical terms, undefined behavior caused by accessing illegal memory regions reflects faults in the program rather than the platform. Such behavior is consistent with other hardware environments.

### Aligned Memory Access

Memory access must be "aligned". The alignment is automatically enforced by all programs compiled
through the official SP1 RISC-V toolchain. SP1's AIRs also constrain that these alignment rules are followed:
- LW/SW memory access must be word aligned. 
- LH/LHU/SH memory access must be half-word aligned.

The RISC-V standard does not explicitly prohibit implementers from requiring aligned memory access, leaving room for such decisions based on specific implementation needs. SP1 enforces memory alignment as part of its design, an approach that aligns with practices in many hardware systems where alignment is standard to optimize performance and simplify implementation.  This design choice is well-documented and does not conflict with RISC-V’s flexibility for implementation-specific optimizations.

In practice, SP1’s memory alignment requirement does not impose a significant burden on developers since it is clearly documented that programs should be compiled with the SP1 toolchain. 

### ECALL Instruction

The ECALL instruction in SP1 is used for system calls and precompiles, adhering to a specific convention for its proper use. Syscall IDs must be valid and loaded into register T0, with arguments placed in registers A0 and A1. If these arguments are memory addresses, they are required to be word-aligned. This convention ensures clarity and consistency in how system calls are handled. Failure to follow these conventions can result in undefined behavior.

### FENCE, WFI, MRET, and CSR related instructions

SP1 marks the FENCE, WFI, MRET, and CSR-related instructions as not implemented and disallowed within the SP1 zkVM. This decision reflects the unique requirements and constraints of SP1's zkVM environment, where these instructions are unnecessary or irrelevant to its intended functionality. By omitting these instructions, SP1 simplifies its implementation, focusing on the subset of RISC-V instructions that are directly applicable to the application.

## Security Considerations

While SP1's customization of RISC-V could theoretically be exploited to cause undefined behavior or divergent execution from other platforms, such scenarios require a deliberately malicious program. The SP1 security model assumes that programs are honestly compiled, as malicious bytecode could otherwise exploit program execution and I/O. Programs which trigger undefined behavior are considered improperly designed for the environment, not evidence of noncompliance in SP1.

In practice, developers are proving their own applications and must be fully aware of the behavior of their source code and the environment they are running in. If an attacker can insert malicious code into a program, there are several trivial ways to control the program's behavior beyond relying on these undefined behaviors to trigger divergent execution. The customizations described in this document do not meaningfully change the attack surface of the SP1 zkVM.
