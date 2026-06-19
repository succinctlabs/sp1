# `libzkevm`

`#![no_std]` Rust rlib whose `extern "C"` exports implement the
[`eth-act/zkvm-standards`](https://github.com/eth-act/zkvm-standards) C ABI
for SP1 guests. The matching staticlib (`libzkevm.a`) is produced by the
sibling [`libzkevm-cabi`](../libzkevm-cabi) crate.

* `crate-type = ["rlib"]`.
* `#![no_std]`; uses `alloc` for a few precompile bodies.
* All 19 accelerator functions in `zkvm_accelerators.h` are implemented;
  see [`src/precompile/mod.rs`](src/precompile/mod.rs) for the dispatch
  table.

See [`../README.md`](../README.md) for the SDK build, ABI overview, and
example guest programs.
