all:
	make build-circuits
	make release-circuits

build-circuits:
	rm -rf build && \
	mkdir -p build && \
	mkdir -p build/groth16 && \
	mkdir -p build/plonk && \
	RUST_LOG=debug \
	cargo run -p sp1-prover --release --bin build_groth16_bn254 -- \
	--build-dir=./build/groth16 && \
	RUST_LOG=debug \
	cargo run -p sp1-prover --release --bin build_plonk_bn254 -- \
	--build-dir=./build/plonk

release-circuits:
	bash release.sh

release-shapes:
	bash shapes.sh

test-e2e:
	RUSTFLAGS='-C target-cpu=native' \
	cargo test --package sp1-prover --lib --release -- tests::test_e2e --exact --show-output 