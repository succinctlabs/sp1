# What is a zkVM?

A zero-knowledge virtual machine (zkVM) is zero-knowledge proof system that allows developers to prove the execution of arbitrary Rust (or other LLVM-compiled language) programs.

Conceptually, you can think of the SP1 zkVM as proving the evaluation of a function `f(x) = y` by following the steps below:

- Define `f` using normal Rust code and compile it to an ELF (covered in the [writing programs](./writing-programs/setup.md) section).
- Setup a proving key (`pk`) and verifying key (`vk`) for the program given the ELF.
- Generate a proof `π` using the SP1 zkVM that `f(x) = y` with `prove(pk, x)`.
- Verify the proof `π` using `verify(vk, x, y, π)`.

As a practical example, `f` could be a simple Fibonacci [program](https://github.com/succinctlabs/sp1/blob/main/examples/fibonacci/program/src/main.rs). The process of generating a proof and verifying it can be seen [here](https://github.com/succinctlabs/sp1/blob/main/examples/fibonacci/script/src/main.rs).

For blockchain applications, the verification usually happens inside of a [smart contract](https://github.com/succinctlabs/sp1-project-template/blob/main/contracts/src/Fibonacci.sol).
