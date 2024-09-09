.PHONY: all test-artifacts

all: test-artifacts

# Build the ELF artifacts used for testing by triggering the `build.rs` script.
# Must be done manually before running Clippy since it does not interact well with SP1's toolchain.
test-artifacts:
	@cargo check -p test-artifacts
