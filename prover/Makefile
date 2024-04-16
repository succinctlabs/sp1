all:
	make fibonacci-sweep
	make tendermint-sweep

fibonacci-sweep:
	mkdir -p scripts/results && \
	RUSTFLAGS='-C target-cpu=native -C target_feature=+avx512ifma,+avx512vl' \
	RUST_LOG=info \
	cargo run --package sp1-prover --release --bin fibonacci_sweep

tendermint-sweep:
	mkdir -p scripts/results && \
	RUSTFLAGS='-C target-cpu=native -C target_feature=+avx512ifma,+avx512vl' \
	RUST_LOG=info \
	cargo run --package sp1-prover --release --bin tendermint_sweep	