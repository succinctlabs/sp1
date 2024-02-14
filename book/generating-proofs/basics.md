# Generating Proofs: Basics

An end-to-end flow of proving `f(x) = y` with the SP1 looks like as follows:

- Define `f` using normal rust code and compile it to a proving key `pk` and a verifying key `vk`.
- Generate a proof `π` using the SP1 that `f(x) = y` with `prove(pk, x)`.
- Verify the proof `π` using `verify(vk, x, y, π)`.

To make this more concrete, let's walk through a simple example of generate a proof for a Fiboancci program inside the zkVM.

## Fibonacci

```rust,noplayground
{{#include ../../examples/fibonacci-io/src/main.rs}}
```