.PHONY: all test-artifacts

all: test-artifacts

# Manually build the ELF artifacts used for testing by calling `cargo prove build`.
# Since Clippy does not interact well with SP1's toolchain, the artifacts must exist before
# Clippy is run. However, `cargo check` works fine.
test-artifacts:
	@cd crates/test-artifacts && make
