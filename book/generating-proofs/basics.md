# Generating Proofs: Basics

An end-to-end flow of proving `f(x) = y` with the SP1 zkVM involves the following steps:

- Define `f` using normal Rust code and compile it to an ELF (covered in the [writing programs](../writing-programs/basics.md) section). 
- Generate a proof `π` using the SP1 zkVM that `f(x) = y` with `prove(ELF, x)`.
- Verify the proof `π` using `verify(ELF, x, y, π)`.

To make this more concrete, let's walk through a simple example of generating a proof for a Fiboancci program inside the zkVM.

## Fibonacci

```rust,noplayground
{{#include ../../examples/fibonacci-io/script/src/main.rs}}
```
