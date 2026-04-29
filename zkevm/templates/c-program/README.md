# zkevm-sdk-c-template

Minimal C guest scaffold for SP1 via the [zkevm-sdk](../../).

## Quick start

```sh
# 1. Download the latest SDK release (or build from source via `make sdk` in the SP1 tree).
wget https://github.com/succinctlabs/sp1/releases/download/zkevm-sdk-vX.Y.Z/zkevm-sdk-vX.Y.Z.tar.gz
tar xzf zkevm-sdk-vX.Y.Z.tar.gz

# 2. Copy this template wherever you want.
cp -r zkevm/templates/c-program my-project
cd my-project

# 3. Edit main.c with your guest logic.
$EDITOR main.c

# 4. Build.
make SDK_DIR=../zkevm-sdk-vX.Y.Z
# -> writes `guest.elf`

# 5. Run / prove via SP1's SDK (see ../../examples/hello-c/script for a
#    template host driver).
```

## What you get

* `main.c` — skeleton calling `read_input` / `write_output` (eth-act
  zkvm-standards IO interface).
* `Makefile` — clang + ld.lld pipeline for the
  `riscv64im-succinct-zkvm-elf` target.

## Tooling

* `clang` with the riscv64 backend (LLVM 9+ ships with it).
* `ld.lld` (`apt install lld` on Debian/Ubuntu, or comes with the SP1
  toolchain via `sp1up`).

## Termination semantics

* `int main(void) { return 0; }` — clean termination, exit code 0.
* `return non_zero;` — failed termination, exit code propagated to the
  verifier per the eth-act standard.
* `abort()` — equivalent to `zkvm_halt(1)`.

## Available precompiles

See [`zkvm_accelerators.h`](../../include/zkvm_accelerators.h) for the
full list. Implementation status of each `zkvm_*` function is tracked
in the [zkevm-sdk README](../../README.md).
