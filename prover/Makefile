all:
	make fibonacci-sweep
	make tendermint-sweep
	make fibonacci-groth16

groth16:
	RUST_LOG=info RUSTFLAGS='-C target-cpu=native' \
	cargo run -p sp1-prover --release --bin e2e -- \
	--build-dir=./build

fibonacci-sweep:
	mkdir -p scripts/results && \
	rm -f scripts/results/fibonacci_sweep.log && \
	RUSTFLAGS='-C target-cpu=native -C target_feature=+avx512ifma,+avx512vl' \
	RUST_LOG=info \
	cargo run --package sp1-prover --release --bin fibonacci_sweep

tendermint-sweep:
	mkdir -p scripts/results && \
	rm -f scripts/results/tendermint_sweep.log && \
	RUSTFLAGS='-C target-cpu=native -C target_feature=+avx512ifma,+avx512vl' \
	RUST_LOG=info \
	cargo run --package sp1-prover --release --bin tendermint_sweep	

fibonacci-groth16:
	mkdir -p scripts/results && \
	RUSTFLAGS='-C target-cpu=native -C target_feature=+avx512ifma,+avx512vl' \
	RUST_LOG=info \
	cargo run --package sp1-prover --release --bin fibonacci_groth16