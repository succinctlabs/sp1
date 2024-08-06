# What is a zkVM?

A zero-knowledge virtual machine (zkVM) is zero-knowledge proof system that allows developers to prove the execution of arbitrary Rust (or other LLVM-compiled language) programs.

Conceptually, you can think of the SP1 zkVM as proving the evaluation of a function `f(x) = y` by following the steps below:

- Define `f` using normal Rust code and compile it to an ELF (covered in the [writing programs](./writing-programs/setup.md) section).
- Setup a proving key (`pk`) and verifying key (`vk`) for the program given the ELF.
- Generate a proof `π` using the SP1 zkVM that `f(x) = y` with `prove(pk, x)`.
- Verify the proof `π` using `verify(vk, x, y, π)`.

As a practical example, `f` could be a simple Fibonacci [program](https://github.com/succinctlabs/sp1/blob/main/examples/fibonacci/program/src/main.rs). The process of generating a proof and verifying it can be seen [here](https://github.com/succinctlabs/sp1/blob/main/examples/fibonacci/script/src/main.rs).

For blockchain applications, the verification usually happens inside of a [smart contract](https://github.com/succinctlabs/sp1-project-template/blob/main/contracts/src/Fibonacci.sol).

## How does SP1 Work?

At a high level, SP1 works with the following steps:

* Write a program in Rust that defines the logic of your computation for which you want to generate a ZKP.
* Compile the program to the RISC-V ISA (a standard Rust compilation target) using the `cargo prove` CLI tool (installation instructions [here](./getting-started/install.md)) and generate a RISC-V ELF file.
* SP1 will prove the correct execution of arbitrary RISC-V programs by generating a STARK proof of execution.
* Developers can leverage the `sp1-sdk` crate to generate proofs with their ELF and input data. Under the hood the `sp1-sdk` will either generate proofs locally or use a beta version of Succinct's prover network to generate proofs.

SP1 leverages performant STARK recursion that allows us to prove the execution of arbitrarily long programs and also has a STARK -> SNARK "wrapping system" that allows us to generate small SNARK proofs that can be efficiently verified on EVM chains.

## Proof System 

For more technical details, check out the SP1 technical note that explains our proof system in detail. In short, we use:

* STARKs + FRI over the Baby Bear field
* We use performant STARK recursion that allows us to prove the execution of arbitrarily long programs
* We have a system of performant precompiles that accelerate hash functions and cryptographic signature verification that allow us to get substantial performance gains on blockchain workloads


