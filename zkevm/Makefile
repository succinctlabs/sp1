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

sdk:
	cd .. && $(CARGO) run --release -p zkevm-build-sdk

# A redistributable tarball of the SDK output. Contents:
#   zkevm-sdk-<version>/{libzkevm.a, zkvm.ld, include/zkvm_accelerators.h, README.md}
# Override SDK_VERSION on the command line (the GitHub Actions workflow
# sets it from the pushed tag).
SDK_VERSION ?= 0.1.0-pre
.PHONY: sdk-archive
sdk-archive: sdk
	@stage="zkevm-sdk-$(SDK_VERSION)"; \
	rm -rf "$$stage" "$$stage.tar.gz"; \
	mkdir -p "$$stage/include"; \
	cp $(SDK_DIR)/libzkevm.a "$$stage/"; \
	cp $(SDK_DIR)/zkvm.ld "$$stage/"; \
	cp $(SDK_DIR)/include/zkvm_accelerators.h "$$stage/include/"; \
	cp templates/sdk-archive-README.md "$$stage/README.md"; \
	tar -czf "$$stage.tar.gz" "$$stage"; \
	rm -rf "$$stage"; \
	echo "wrote $$stage.tar.gz ($$(du -h $$stage.tar.gz | cut -f1))"

# `make sdk` populates everything via the `zkevm-build-sdk` helper bin
# (uses `sp1_build::build_program_staticlib` under the hood — the only
# reliable way to invoke the succinct toolchain on libzkevm-cabi from a
# Makefile, since rustup's `cargo +succinct` fallback paths look for a
# `rust-src` component that isn't shipped).

example: example-c example-rust

example-c: sdk
	$(MAKE) -C examples/hello-c/program SDK_DIR=$(abspath $(SDK_DIR))

example-rust:
	cd examples && $(CARGO) build --release --target $(TARGET) -p hello-rust

# Run the host execute/prove scripts. Each script's `build.rs` builds
# its corresponding guest ELF as a side effect, so just `cargo run` works.
.PHONY: example-hello-rust-execute example-hello-rust-prove \
        example-hello-c-execute example-hello-c-prove \
        example-fibonacci-execute example-fibonacci-prove \
        example-panic-execute \
        example-keccak-execute example-keccak-prove \
        example-sha256-execute example-sha256-prove \
        example-fibonacci-c-execute example-fibonacci-c-prove \
        example-panic-c-execute \
        example-keccak-c-execute example-keccak-c-prove \
        example-sha256-c-execute example-sha256-c-prove

example-hello-rust-execute:
	cd examples && $(CARGO) run --release -p hello-rust-script --bin hello-rust-execute

example-hello-rust-prove:
	cd examples && $(CARGO) run --release -p hello-rust-script --bin hello-rust-prove

example-hello-c-execute:
	cd examples && $(CARGO) run --release -p hello-c-script --bin hello-c-execute

example-hello-c-prove:
	cd examples && $(CARGO) run --release -p hello-c-script --bin hello-c-prove

example-fibonacci-execute:
	cd examples && $(CARGO) run --release -p fibonacci-script --bin fibonacci-execute

example-fibonacci-prove:
	cd examples && $(CARGO) run --release -p fibonacci-script --bin fibonacci-prove

example-panic-execute:
	cd examples && $(CARGO) run --release -p panic-script --bin panic-execute

example-keccak-execute:
	cd examples && $(CARGO) run --release -p keccak-script --bin keccak-execute

example-keccak-prove:
	cd examples && $(CARGO) run --release -p keccak-script --bin keccak-prove

example-sha256-execute:
	cd examples && $(CARGO) run --release -p sha256-script --bin sha256-execute

example-sha256-prove:
	cd examples && $(CARGO) run --release -p sha256-script --bin sha256-prove

example-fibonacci-c-execute:
	cd examples && $(CARGO) run --release -p fibonacci-c-script --bin fibonacci-c-execute

example-fibonacci-c-prove:
	cd examples && $(CARGO) run --release -p fibonacci-c-script --bin fibonacci-c-prove

example-panic-c-execute:
	cd examples && $(CARGO) run --release -p panic-c-script --bin panic-c-execute

example-keccak-c-execute:
	cd examples && $(CARGO) run --release -p keccak-c-script --bin keccak-c-execute

example-keccak-c-prove:
	cd examples && $(CARGO) run --release -p keccak-c-script --bin keccak-c-prove

example-sha256-c-execute:
	cd examples && $(CARGO) run --release -p sha256-c-script --bin sha256-c-execute

example-sha256-c-prove:
	cd examples && $(CARGO) run --release -p sha256-c-script --bin sha256-c-prove

clean:
	$(CARGO) clean --manifest-path libzkevm/Cargo.toml || true
	cd $(CABI_DIR) && $(CARGO) clean || true
	cd examples && $(CARGO) clean || true
	rm -rf $(SDK_DIR)
	$(MAKE) -C examples/hello-c/program clean SDK_DIR=$(abspath $(SDK_DIR)) || true
