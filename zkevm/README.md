# SP1 zkEVM SDK (scaffolding)

Platform SDK that lets a non-Rust guest (C / TinyGo / Zig / …) target
[SP1](https://github.com/succinctlabs/sp1) against the
[`eth-act/zkvm-standards`](https://github.com/eth-act/zkvm-standards) C ABI.

> **Status: scaffolding.** The `extern "C"` ABI symbols, runtime
> integration with `sp1-zkvm`, and build pipeline are all wired and
> compile clean. Precompile bodies are still stubs that return
> `ZKVM_EFAIL` — humans need to fill those in (see TODOs).

## What this gives you

```
sdk/
├── libzkevm.a              # extern "C" implementations + sp1-zkvm runtime
├── zkvm.ld                 # linker script for SP1's memory map
└── include/
    └── zkvm_accelerators.h # upstream eth-act header, copied verbatim
```

`_start` is supplied by `sp1-zkvm` (bundled into `libzkevm.a`); no
separate `crt0.o` is needed. A C consumer's link line is:

```sh
clang --target=riscv64-unknown-none-elf -march=rv64im -mabi=lp64 \
      -ffreestanding -nostdinc -I sdk/include -c main.c -o main.o
ld.lld -nostdlib -static -T sdk/zkvm.ld -L sdk \
       main.o -lzkevm -o guest.elf
```

## Building

```sh
make                              # produces sdk/{libzkevm.a, zkvm.ld, headers}
make example                      # builds both hello-c and hello-rust guests
make example-c                    # just the C example (clang + ld.lld)
make example-rust                 # just the Rust example guest (cargo)

# Per-example execute / prove scripts (each script's build.rs handles
# the guest build via sp1-build, so no `make sdk` step is required):
make example-hello-rust-execute   # IO + termination round-trip (Rust)
make example-hello-rust-prove     # ... and prove + verify
make example-hello-c-execute      # IO + termination round-trip (C)
make example-hello-c-prove        # ... and prove + verify
make example-fibonacci-execute    # arithmetic + IO (Rust)
make example-fibonacci-prove      # ... and prove + verify
make example-panic-execute        # failed-termination via panic! (Rust)
make example-keccak-execute       # zkvm_keccak256 precompile, against host reference
make example-keccak-prove         # ... and prove + verify (exercises KECCAK_PERMUTE circuit)

make clean
```

Default target: `riscv64im-succinct-zkvm-elf` (SP1's tier-3 triple,
installed by `sp1up`).

### End-to-end smoke tests

Successful termination (compute + IO):

```sh
$ make example-hello-rust-execute
INFO executed hello-rust cycles=4674 ...
INFO public output output=hello from the host
INFO output matches input

$ make example-fibonacci-execute
INFO executed fibonacci cycles=18726 n=1000 fib_mod_7919=5965

$ make example-fibonacci-prove
INFO generated core proof n=1000 fib_mod_7919=5965
INFO proof verified
```

Failed termination (panic):

```sh
$ make example-panic-execute
INFO flag=0: clean termination cycles=4678 output=no panic
INFO flag=1: executor returned Ok — guest halted with non-zero exit code cycles=8663
```

First non-stub precompile — `zkvm_keccak256` against a host reference:

```sh
$ make example-keccak-execute
INFO executed keccak input_len=0   cycles=4826 keccak_permute_calls=1
INFO executed keccak input_len=11  cycles=4905 keccak_permute_calls=1
INFO executed keccak input_len=136 cycles=5797 keccak_permute_calls=2
INFO executed keccak input_len=200 cycles=6248 keccak_permute_calls=2
INFO executed keccak input_len=43  cycles=5129 keccak_permute_calls=1
INFO all digests match host-computed keccak256
```

The sponge construction (absorb / pad / squeeze) lives in
[`libzkevm/src/precompile/hash.rs`](libzkevm/src/precompile/hash.rs);
each call to the inner keccak-f[1600] permutation goes through SP1's
`KECCAK_PERMUTE` syscall (`t0 = 0x00_01_01_09`). This is the general
pattern: most accelerators wrap one or more low-level precompile
syscalls plus some software bookkeeping.

The same C-ABI path is exercised by [`hello-c`](examples/hello-c/) (a
`int main(void)` linked through `clang` + `ld.lld` against
`libzkevm.a`).

Together these validate the full pipeline: `sp1-zkvm`'s `_start` →
`__start` (forwarding `main`'s `i32` exit code) → C-ABI `main` →
libzkevm's `read_input`/`write_output` against SP1's hint stream and
public-values hasher → `syscall_halt` → digest commit → STARK proof →
verification.

## Layout

```
zkevm/
├── Makefile                # top-level build
├── README.md
├── include/
│   └── zkvm_accelerators.h # vendored upstream header
├── zkvm.ld                 # linker script
├── libzkevm/               # rlib (member of the SP1 root workspace)
│   ├── Cargo.toml          #   - depends on sp1-zkvm (no_std)
│   └── src/                #   - all extern "C" implementations live here
│       ├── lib.rs
│       ├── ecall.rs
│       ├── halt.rs
│       ├── io.rs
│       ├── status.rs
│       └── precompile/
├── libzkevm-cabi/          # staticlib facade (own workspace, panic=abort)
│   ├── Cargo.toml
│   └── src/lib.rs          #   re-exports libzkevm + supplies panic_handler
└── examples/
    ├── hello-c/             # IO + termination round-trip (C)
    │   ├── program/         #   freestanding C, links sdk/libzkevm.a
    │   └── script/          #   build.rs runs sp1-build + clang + ld.lld
    ├── hello-rust/          # IO + termination round-trip (Rust)
    │   ├── program/         #   `#![no_main]` guest using zkevm::entrypoint!
    │   └── script/          #   execute + prove
    ├── fibonacci/           # arithmetic + IO (Rust)
    │   ├── program/
    │   └── script/
    ├── panic/               # failed termination via panic (Rust)
    │   ├── program/
    │   └── script/
    └── keccak/              # `zkvm_keccak256` precompile demo (Rust)
        ├── program/
        └── script/
```

Each example follows the same shape: `program/` is the `riscv64im-succinct-zkvm-elf`
guest (its own workspace, `panic = "abort"`); `script/` is a member of
the SP1 root workspace whose `build.rs` builds the guest via
`sp1_build::build_program("../program")` and whose binaries drive
`client.execute(...)` / `client.prove(...)`.

### Why three workspaces?

* `libzkevm` is in the **SP1 root workspace** so it can depend on
  `sp1-zkvm` directly (now `no_std`) and reuse the patched no-std crypto
  crates (`sha2`, `sha3`, `crypto-bigint`, …) when implementing
  precompile bodies.
* `libzkevm-cabi` lives in its **own workspace** because a `#![no_std]`
  staticlib requires `panic = "abort"`, which cargo only supports as a
  workspace-level setting.
* `examples/hello-rust` lives in its **own workspace** for the same
  reason (it's a `#![no_std] #![no_main]` binary).

### What changed in SP1 to make this possible

This SDK required two small SP1 refactors:

* `sp1-primitives` is now `#![no_std]` (uses `extern crate alloc` for
  `Vec`/`String` helpers). Slop crates' internal `std::*` usage doesn't
  leak through the public API surface, so the cascade was contained.
* `sp1-zkvm` is now `#![no_std]`. `std::ptr/alloc/sync` references in
  `lib.rs`, `syscalls/memory.rs`, and `syscalls/sys.rs` swapped to
  `core::`/`alloc::` equivalents. The `sys_rand` PRNG dropped its
  `Mutex<StdRng>` (zkVM is single-threaded; `static mut` is fine).

Both changes are backward-compatible — host-side consumers see no
difference because they always have `std` available. Verified with
`cargo check --workspace` and `cargo build` against existing targets.

## ABI notes

* **Target triple**: SP1 uses `riscv64im-succinct-zkvm-elf` (RV64IM,
  LP64, soft-float). Same ISA as eth-act's proposed
  `riscv64im_zicclsm-unknown-none-elf`.
* **Calling convention**: standard RISC-V LP64.
* **Syscall ABI** (`crates/zkvm/entrypoint/src/syscalls/`):
  * `ecall` instruction, syscall number in `t0`, args in `a0..a7`.
  * Return value in `t0` (lateout) or via an out-pointer in `a0`.
* **Memory map** (`zkvm.ld`):
  * `.text` starts at `0x0000_1000` (skips the null page).
  * `__stack_top = 0x7800_0000`, matching
    `sp1_primitives::consts::STACK_TOP`.
* **Public-values hashing**: `write_output` delegates to
  `sp1_zkvm::syscalls::syscall_write` against `FD_PUBLIC_VALUES = 13`,
  which feeds the public-values Sha256 hasher. `zkvm_halt` delegates to
  `sp1_zkvm::syscalls::syscall_halt`, which commits the digest before
  issuing the HALT ecall. Both come for free from the SP1 runtime.

## Termination semantics

* `zkvm_halt(uint8_t exit_code)` → `sp1_zkvm::syscalls::syscall_halt`.
  Commits public-values digest + deferred-proofs digest, then halts
  with the given exit code. Never returns.
* `exit`, `_exit`, `abort` are aliases that route to `zkvm_halt`.
* `int main(void)`'s return value flows through SP1's `__start` to the
  HALT exit code — `return 0;` halts cleanly, `return non_zero;`
  signals "failed termination" per the eth-act spec. No explicit
  `zkvm_halt` call needed.

## Compiler-rt / freestanding shims

A C program built freestanding will need a handful of helpers that
aren't covered by the standard:

* String/memory: `memcpy`, `memset`, `memmove`, `memcmp`
* 64-bit divmod: `__udivdi3`, `__divdi3`, `__umoddi3`, `__moddi3`
* 128-bit shifts (rare): `__ashlti3`, `__lshrti3`, `__ashrti3`

**Decision point**: vendor LLVM `compiler-rt` builtins (link
`libclang_rt.builtins-riscv64.a`) or vendor picolibc's `string.[ch]`.
The SP1 Rust entrypoint already has `memcpy.s` (and a commented-out
`memset.s`) under `crates/zkvm/entrypoint/src/`; lift those if you want
a minimal mem-only shim layer.

## Open TODOs (not for this scaffold)

1. **Precompile bodies.** Every function in `libzkevm/src/precompile/*`
   is a stub that issues a placeholder `0xDEAD_*` ecall and returns
   `ZKVM_EFAIL`. The suggested SP1 mapping per function is in
   `libzkevm/src/precompile/mod.rs`. The implementation strategy is to
   call SP1's patched no-std crypto crates (`sha2`, `sha3`,
   `crypto-bigint`, `k256`, `p256`, `bn`, `bls12_381`, `c-kzg`, …) which
   already wrap the precompile syscalls.
2. **`read_input` semantics.** Currently caches one chunk from the SP1
   hint stream. The eth-act spec says the function is idempotent and
   returns the same buffer on every call — this works, but if a guest
   needs multiple input chunks it will need to read additional ones via
   `sp1_zkvm` directly.
3. **Ecall numbers for new precompiles.** `zkvm_modexp`, `zkvm_blake2f`,
   `zkvm_kzg_point_eval`, `zkvm_bls12_map_fp{,2}_to_g{1,2}` have no SP1
   syscall today. Either implement in software on top of existing
   precompiles or extend the SP1 runtime with new syscall numbers.
5. **compiler-rt sourcing.** Pick LLVM builtins vs picolibc.
6. **Confirm an actual built ELF runs / proves under SP1.** The current
   scaffold's CI checks `cargo check`; a follow-up should run
   `make example && sp1 prove` end-to-end.

## References

* SP1 entrypoint and syscall list:
  [`crates/zkvm/entrypoint/src/`](../crates/zkvm/entrypoint/src/) and
  [`crates/zkvm/entrypoint/src/syscalls/mod.rs`](../crates/zkvm/entrypoint/src/syscalls/mod.rs)
* SP1 memory constants:
  [`crates/primitives/src/consts.rs`](../crates/primitives/src/consts.rs)
* eth-act standards:
  [`/standards/c-interface-accelerators/zkvm_accelerators.h`](https://github.com/eth-act/zkvm-standards/blob/main/standards/c-interface-accelerators/zkvm_accelerators.h),
  [`/standards/io-interface/`](https://github.com/eth-act/zkvm-standards/tree/main/standards/io-interface),
  [`/standards/standard-termination-semantics/`](https://github.com/eth-act/zkvm-standards/tree/main/standards/standard-termination-semantics),
  [`/standards/memory-layout-restrictions/`](https://github.com/eth-act/zkvm-standards/tree/main/standards/memory-layout-restrictions),
  [`/standards/riscv-target/target.md`](https://github.com/eth-act/zkvm-standards/blob/main/standards/riscv-target/target.md).
