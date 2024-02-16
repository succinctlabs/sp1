RUST_LOG=debug cargo test --package sp1-core --lib -- syscall::precompiles::blake3::compress::compress_tests::prove_babybear --exact --nocapture
