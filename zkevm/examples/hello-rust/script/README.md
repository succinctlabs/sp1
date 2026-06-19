# hello-rust-script

Host-side script that builds the sibling [`program/`](../program/) guest,
executes it under SP1's executor, and (with `--bin hello-rust-prove`)
generates and verifies a core STARK proof.

## Run

From the SP1 root:

```sh
# Execute only — fastest, no proof
cargo run --release -p hello-rust-script --bin hello-rust-execute

# Or via the SDK Makefile (equivalent, runs from anywhere):
make -C zkevm example-rust-execute

# Generate + verify a CPU proof (slow)
cargo run --release -p hello-rust-script --bin hello-rust-prove
make -C zkevm example-rust-prove

# Same with mock prover (skips real proving — won't pass `client.verify`)
SP1_PROVER=mock cargo run --release -p hello-rust-script --bin hello-rust-execute
```

## Wiring

* The guest ELF is built by [`build.rs`](build.rs) via
  `sp1_build::build_program("../program")` and surfaced via
  `include_elf!("hello-rust")`.
* The host pushes the entire private input as a single chunk via
  `stdin.write_slice(...)`. This matches `libzkevm::io::read_input`'s
  one-chunk contract (see `libzkevm/src/io.rs`).
* The guest's `write_output` writes to `FD_PUBLIC_VALUES = 13` via
  `sp1_zkvm::syscalls::syscall_write`, which feeds the public-values
  hasher; `syscall_halt` then commits the digest before HALT.
* `main`'s `i32` return value flows through `__start` to the HALT exit
  code, per the eth-act standard-termination spec.
