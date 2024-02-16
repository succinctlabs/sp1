RUST_LOG=debug cargo test --package sp1-core --lib -- syscall::precompiles::blake3::compress::compress_tests::test_blake3_compress_inner_elf --exact --nocapture
