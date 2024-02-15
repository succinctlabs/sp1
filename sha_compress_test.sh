RUST_LOG=debug cargo test --package sp1-core --release --lib -- syscall::precompiles::sha256::compress::compress_tests::prove_babybear --exact --nocapture
