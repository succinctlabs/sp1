all:
	make build-plonk-bn254
	make release-plonk-bn254

build-plonk-bn254:
	rm -rf build && \
	mkdir -p build && \
	RUSTFLAGS='-C target-cpu=native' \
	cargo run -p sp1-prover --release --bin build_plonk_bn254 --features plonk -- \
	--build-dir=./build

release-plonk-bn254:
	bash release.sh

test-e2e:
	RUSTFLAGS='-C target-cpu=native' \
	cargo test --package sp1-prover --lib --release -- tests::test_e2e --exact --show-output 