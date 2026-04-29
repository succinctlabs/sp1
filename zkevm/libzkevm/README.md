# `libzkevm`

`#![no_std]` Rust staticlib whose `extern "C"` exports implement the
[`eth-act/zkvm-standards`](https://github.com/eth-act/zkvm-standards) C ABI
for SP1 guests.

* `crate-type = ["staticlib"]` → produces `libzkevm.a`.
* `panic = "abort"` (workspace profile).
* No `std`, no `alloc`, no allocator.

See `../README.md` for build instructions and the open TODO list.
