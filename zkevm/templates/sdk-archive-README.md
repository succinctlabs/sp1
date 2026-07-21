# zkevm-sdk

Pre-built artifacts for writing C/Go/Zig guest programs that target
[SP1](https://github.com/succinctlabs/sp1) against the
[`eth-act/zkvm-standards`](https://github.com/eth-act/zkvm-standards) C ABI.

## Contents

```
libzkevm.a            extern "C" implementations + sp1-zkvm runtime (RV64IM)
zkvm.ld               linker script (ENTRY(_start) → sp1-zkvm)
include/
  zkvm_accelerators.h vendored eth-act header
```

## Linking

A C consumer's link line is:

```sh
clang --target=riscv64-unknown-none-elf -march=rv64im -mabi=lp64 \
      -ffreestanding -fno-builtin -fno-stack-protector -nostdlibinc \
      -I include -c main.c -o main.o
ld.lld -nostdlib -static -T zkvm.ld -o guest.elf main.o libzkevm.a
```

A ready-to-use scaffold lives at
[`zkevm/templates/c-program/`](https://github.com/succinctlabs/sp1/tree/main/zkevm/templates/c-program)
in the SP1 source tree — copy that directory and edit `main.c`.

## Tooling

* `clang` (with the riscv64 backend; LLVM 9+ ships with it).
* `ld.lld` (install with `apt install lld` on Debian/Ubuntu, or use
  the bundled copy in any SP1 toolchain installed via `sp1up`).

## Running under SP1

To execute or prove the resulting `guest.elf`, write a small host
script using `sp1-sdk` (see
[`zkevm/examples/hello-c/script/`](https://github.com/succinctlabs/sp1/tree/main/zkevm/examples/hello-c/script)
in the source tree for a template).

## Status

Scaffolding. Most precompile bodies in `libzkevm.a` are still stubs
that return `ZKVM_EFAIL` — see the SDK README in the SP1 source tree
for the implementation status of each `zkvm_*` accelerator.
