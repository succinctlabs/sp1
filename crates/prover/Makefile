all:
	make build-circuits
	make release-circuits

build-circuits:
	rm -rf build && \
	mkdir -p build && \
	RUSTFLAGS='-C target-cpu=native' \
	cargo run -p sp1-prover --release --bin build_plonk_bn254 --features native-gnark -- \
	--build-dir=./build && \
	RUSTFLAGS='-C target-cpu=native' \
	cargo run -p sp1-prover --release --bin build_groth16_bn254 --features native-gnark -- \
	--build-dir=./build

release-circuits:
	@read -p "Release version (ex. v1.0.0-testnet)? " version; \
	bash release.sh $$version

test-e2e:
	RUSTFLAGS='-C target-cpu=native' \
	cargo test --package sp1-prover --lib --release -- tests::test_e2e --exact --show-output 
