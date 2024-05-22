all:
	make export-groth16-verifier

export-groth16-verifier:
	RUSTFLAGS='-C target-cpu=native' \
	cargo run -p sp1-sdk --release --bin export_verifier -- \
	--output-dir=../contracts/src

