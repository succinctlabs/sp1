all:
	make fri-sweep

fri-sweep:
	mkdir -p experiments/results && \
	RUSTFLAGS='-C target-cpu=native -C target_feature=+avx512ifma,+avx512vl' \
	RUST_LOG=info \
	cargo run --package sp1-recursion-program --release --bin fri_sweep