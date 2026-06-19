# SP1 zkEVM SDK

C-callable SP1 runtime + accelerator implementations matching the
[`eth-act/zkvm-standards`](https://github.com/eth-act/zkvm-standards) C
ABI. Lets a non-Rust guest (C, TinyGo, Zig, …) target SP1 by linking
one staticlib against a stable header.

## What you get

```
sdk/
├── libzkevm.a              extern "C" implementations + sp1-zkvm runtime (RV64IM)
├── zkvm.ld                 linker script (ENTRY(_start) → sp1-zkvm)
└── include/
    ├── zkvm_accelerators.h vendored eth-act header
    └── assert.h            freestanding `<assert.h>` shim
```

`_start`, the embedded allocator, the public-values hasher, and the
hint-stream IO are all bundled inside `libzkevm.a` — no separate `crt0.o`,
no Rust-side wrapper required.

### Accelerator status

| Function | Backing |
|---|---|
| `zkvm_keccak256` | patched `tiny-keccak` → `KECCAK_PERMUTE` syscall |
| `zkvm_sha256` | patched `sha2` → `SHA_EXTEND` + `SHA_COMPRESS` |
| `zkvm_ripemd160` | stock `ripemd` (software, not perf-critical for L1) |
| `zkvm_secp256k1_{verify,ecrecover}` | patched `k256` → `SECP256K1_*` |
| `zkvm_secp256r1_verify` | patched `p256` → `SECP256R1_*` |
| `zkvm_bn254_g1_{add,mul}`, `zkvm_bn254_pairing` | patched `substrate-bn` → `BN254_*` |
| `zkvm_bls12_*` (G1/G2 add/MSM, pairing, map-to-curve) | patched `bls12_381` → `BLS12381_*` |
| `zkvm_modexp` | software via `num-bigint-dig` |
| `zkvm_blake2f` | software F compression (RFC 7693 §3.2) |
| `zkvm_kzg_point_eval` | `kzg-rs` with Ethereum trusted setup |

See [`libzkevm/src/precompile/mod.rs`](libzkevm/src/precompile/mod.rs)
for the per-function dispatch detail.

## Quick start

```sh
make sdk           # produces sdk/{libzkevm.a, zkvm.ld, include/}
make sdk-archive   # plus zkevm-sdk-vX.Y.Z.tar.gz for redistribution
```

C consumer's link line:

```sh
clang --target=riscv64-unknown-none-elf -march=rv64im -mabi=lp64 \
      -ffreestanding -fno-builtin -fno-stack-protector -nostdlibinc \
      -I sdk/include -c main.c -o main.o
ld.lld -nostdlib -static -T sdk/zkvm.ld -L sdk \
       main.o -lzkevm -o guest.elf
```

The [`templates/c-program/`](templates/c-program/) directory is a
ready-to-`cp` scaffold (`Makefile + main.c + README.md`) for a fresh
project.

### Running an example

```sh
make example-keccak-c-execute
```

Each example pairs a guest (`program/`) with a host driver
(`script/`); the script's `build.rs` builds the guest via
`sp1_build`, the binaries run `client.execute(...)` /
`client.prove(...)`. Use `SP1_PROVER=cuda` (or `network`) to pick a
faster prover for the prove variants.

## Layout

```
zkevm/
├── Makefile                top-level build
├── zkvm.ld                 linker script
├── include/                vendored headers (zkvm_accelerators.h, assert.h)
├── libzkevm/               rlib (member of the SP1 root workspace)
│   └── src/                  ecall + halt + io + precompile/* implementations
├── libzkevm-cabi/          staticlib facade (own workspace, panic=abort)
├── build-sdk/              `cargo run -p zkevm-build-sdk` → stages sdk/
├── examples/               see below
└── templates/
    └── c-program/          minimal C-guest scaffold for downstream users
```

### Examples

`examples/` is its own workspace (`examples/Cargo.toml`); every
example's program + script is a member.

| Example | Demonstrates |
|---|---|
| `hello-{rust,c}` | IO round-trip + termination |
| `fibonacci{,-c}` | arithmetic + IO |
| `panic{,-c}`, `assert-c`, `exit-code-c` | failed-termination paths |
| `keccak{,-c}`, `sha256{,-c}`, `ripemd-c` | hash precompiles |
| `secp256k1-c`, `secp256r1-c`, `ecrecover-c` | ECDSA + ecrecover |
| `bn254-c`, `bls12-c` | elliptic-curve precompiles + pairings |
| `modexp-c`, `blake2f-c`, `kzg-c` | remaining EVM precompiles |
| `c-build`, `fixtures` | shared infrastructure (not user-facing) |

`fixtures/` vendors KZG (consensus-specs), Wycheproof ECDSA, and EIP-152
BLAKE2f test vectors so the per-example execute scripts can do
differential checks against host-computed references.

### Why three workspaces

- **SP1 root** owns `libzkevm/` (rlib) — needs to depend on `sp1-zkvm`
  via `workspace = true` and reuse SP1's patched no-std crypto crates.
- **`libzkevm-cabi/`** is its own workspace — `#![no_std]` staticlibs
  require `panic = "abort"`, which cargo only honors at workspace
  scope.
- **`examples/`** is its own workspace — keeps host-side example deps
  (`sp1-sdk`, `tokio`, `tracing`, etc.) out of the SP1 root, mirrors
  the existing `examples/` pattern in the SP1 source tree.

## ABI

- **Target triple**: `riscv64im-succinct-zkvm-elf` (RV64IM, LP64,
  soft-float). ISA-equivalent to eth-act's
  `riscv64im_zicclsm-unknown-none-elf`.
- **Syscall**: `ecall` with the syscall number in `t0`, args in
  `a0..a7`. Return values via `t0` (lateout) or `a0` out-pointer. See
  [`crates/zkvm/entrypoint/src/syscalls/mod.rs`](../crates/zkvm/entrypoint/src/syscalls/mod.rs)
  for the assigned numbers.
- **Memory map**: `.text` at `0x7800_0000` (= `STACK_TOP`); stack
  grows down from there into addresses below; the SP1 executor rejects
  ELFs with segments below `STACK_TOP`.
- **IO**: `read_input` returns the first chunk in SP1's hint stream.
  The host MUST push the entire private input as a single
  `stdin.write_slice(...)` call. `write_output` pipes bytes to
  `FD_PUBLIC_VALUES = 13`, which feeds the public-values Sha256
  hasher.

## Termination

- `zkvm_halt(uint8_t exit_code)` → `sp1_zkvm::syscalls::syscall_halt`.
  Commits the public-values + deferred-proofs digests, then halts.
- `int main(void)`'s return value flows through SP1's `__start` to the
  HALT exit code automatically — `return 0;` halts cleanly,
  `return non_zero;` signals a "failed termination" per the eth-act
  spec.
- `exit`, `_exit`, `abort`, and `__assert_fail` are all aliases that
  route to `zkvm_halt`.

## Compiler-rt

A C guest will need a handful of freestanding helpers (`memcpy`,
`memset`, `memmove`, `memcmp`, the 64-bit divmod intrinsics) that
aren't in the eth-act standard. libzkevm currently provides
`memcpy` + `memset` (lifted from sp1-zkvm); other intrinsics come from
linking against LLVM `compiler-rt`'s `libclang_rt.builtins-riscv64.a`
when needed.

## Limitations / future work

- **`__start` ignores host-side feature gates.** The exit-code
  propagation handles success/failure correctly, but more nuanced
  termination metadata (e.g., distinct "verification failed" vs "proof
  malformed") requires extending sp1-zkvm.
- **Software-only accelerators.** `zkvm_ripemd160`, `zkvm_modexp`, and
  `zkvm_blake2f` have no corresponding SP1 syscall and run as pure RV64
  software. The wrappers can switch to a syscall path without an ABI
  change if one is added later.
- **`bls12_381` map-to-curve uses the upstream `experimental` feature.**
  The patched `bls12_381` crate gates `MapToCurve` behind its
  `experimental` feature flag, which we enable. Tracks any future
  stabilisation of that API.

## References

- SP1 syscalls + entrypoint: [`crates/zkvm/entrypoint/`](../crates/zkvm/entrypoint/)
- SP1 memory constants: [`crates/primitives/src/consts.rs`](../crates/primitives/src/consts.rs)
- eth-act standards: [c-interface-accelerators](https://github.com/eth-act/zkvm-standards/blob/main/standards/c-interface-accelerators/zkvm_accelerators.h),
  [io-interface](https://github.com/eth-act/zkvm-standards/tree/main/standards/io-interface),
  [standard-termination-semantics](https://github.com/eth-act/zkvm-standards/tree/main/standards/standard-termination-semantics),
  [memory-layout-restrictions](https://github.com/eth-act/zkvm-standards/tree/main/standards/memory-layout-restrictions),
  [riscv-target](https://github.com/eth-act/zkvm-standards/blob/main/standards/riscv-target/target.md).
