ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

# PHONY means that it doesn't correspond to a file; it always runs the build commands.

.PHONY: build-all
build-all: build-static

.PHONY: run-all
run-all: run-static

.PHONY: build-static
build-static:
	@cd lib/babybear && cargo build --release
	@cp lib/babybear/target/release/libbabybear.a lib/
	go build main.go

.PHONY: run-static
run-static: build-static
	@./main_static

# This is just for running the Rust lib tests natively via cargo
.PHONY: test-rust-lib
test-rust-lib:
	@cd lib/babybear && cargo test -- --nocapture

.PHONY: clean
clean:
	rm -rf main_dynamic main_static lib/libbabybear.so lib/libbabybear.a lib/babybear/target