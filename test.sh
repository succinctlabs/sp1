cargo test --package curta-core --lib --release -- syscall::precompiles::sha256::compress::compress_tests --nocapture && \
    cargo test --package curta-core --lib -- syscall::precompiles::sha256::extend::extend_tests --nocapture  --release
