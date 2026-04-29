# SP1 zkEVM SDK — top-level build.
#
# Targets:
#   make             -> build sdk/ output (libzkevm.a, zkvm.ld, headers)
#   make example     -> build both hello-c and hello-rust against sdk/
#   make example-c   -> just hello-c
#   make example-rust-> just hello-rust
#   make clean       -> remove sdk/ and Cargo build artifacts
#
# Tooling assumed on PATH:
#   - cargo (with the SP1 succinct toolchain installed via `sp1up`)
#   - clang + ld.lld (or riscv64-unknown-elf-{gcc,ld}) for the C example
#
# Note: `_start` is supplied by `sp1-zkvm` (via the libzkevm rlib pulled
# into libzkevm-cabi), not by a separate `crt0.o`. The C example links
# only `libzkevm.a + zkvm.ld + main.o`.

TARGET            ?= riscv64im-succinct-zkvm-elf
CARGO             ?= cargo

SDK_DIR           := sdk
# libzkevm.a is produced by the `libzkevm-cabi` crate (a stand-alone
# workspace under `libzkevm-cabi/`). The rlib `libzkevm` (a member of the
# SP1 root workspace at `../Cargo.toml`) holds the actual implementations;
# `libzkevm-cabi` is the staticlib facade that adds the panic_handler and
# is built with `panic = "abort"`.
CABI_DIR          := libzkevm-cabi
CABI_TARGET_DIR   := $(CABI_DIR)/target/$(TARGET)/release
CABI_STATICLIB    := $(CABI_TARGET_DIR)/libzkevm.a

.PHONY: all sdk example example-c example-rust clean

all: sdk

sdk: $(SDK_DIR)/libzkevm.a $(SDK_DIR)/zkvm.ld $(SDK_DIR)/include/zkvm_accelerators.h

# 1) libzkevm.a — built from the cabi crate (separate workspace, panic=abort).
#    The `succinct` toolchain (installed by `sp1up`) is what defines the
#    `riscv64im-succinct-zkvm-elf` target spec; stock stable rustc doesn't
#    know about it.
$(CABI_STATICLIB): $(CABI_DIR)/Cargo.toml $(CABI_DIR)/src/*.rs libzkevm/Cargo.toml libzkevm/src/*.rs libzkevm/src/precompile/*.rs
	cd $(CABI_DIR) && RUSTUP_TOOLCHAIN=succinct $(CARGO) build --release --target $(TARGET)

$(SDK_DIR)/libzkevm.a: $(CABI_STATICLIB)
	@mkdir -p $(SDK_DIR)
	cp $< $@

# 2) Linker script — copied verbatim. `ENTRY(_start)` resolves to
#    `sp1-zkvm`'s `_start` (bundled into `libzkevm.a`).
$(SDK_DIR)/zkvm.ld: zkvm.ld
	@mkdir -p $(SDK_DIR)
	cp $< $@

# 3) Public headers — sourced from the eth-act standard.
$(SDK_DIR)/include/zkvm_accelerators.h: include/zkvm_accelerators.h
	@mkdir -p $(SDK_DIR)/include
	cp $< $@

example: example-c example-rust

example-c: sdk
	$(MAKE) -C examples/hello-c/program SDK_DIR=$(abspath $(SDK_DIR))

example-rust:
	cd examples/hello-rust/program && $(CARGO) build --release --target $(TARGET)

# Run the host execute/prove scripts. Each script's `build.rs` builds
# its corresponding guest ELF as a side effect, so just `cargo run` works.
.PHONY: example-hello-rust-execute example-hello-rust-prove \
        example-hello-c-execute example-hello-c-prove \
        example-fibonacci-execute example-fibonacci-prove \
        example-panic-execute

example-hello-rust-execute:
	$(CARGO) run --release -p hello-rust-script --bin hello-rust-execute

example-hello-rust-prove:
	$(CARGO) run --release -p hello-rust-script --bin hello-rust-prove

example-hello-c-execute:
	$(CARGO) run --release -p hello-c-script --bin hello-c-execute

example-hello-c-prove:
	$(CARGO) run --release -p hello-c-script --bin hello-c-prove

example-fibonacci-execute:
	$(CARGO) run --release -p fibonacci-script --bin fibonacci-execute

example-fibonacci-prove:
	$(CARGO) run --release -p fibonacci-script --bin fibonacci-prove

example-panic-execute:
	$(CARGO) run --release -p panic-script --bin panic-execute

clean:
	$(CARGO) clean --manifest-path libzkevm/Cargo.toml || true
	cd $(CABI_DIR) && $(CARGO) clean || true
	cd examples/hello-rust/program && $(CARGO) clean || true
	rm -rf $(SDK_DIR)
	$(MAKE) -C examples/hello-c/program clean SDK_DIR=$(abspath $(SDK_DIR)) || true
