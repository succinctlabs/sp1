# Updating Rust to version 1.82.0
rustup toolchain install 1.82.0
rustup default 1.82.0

# Ensure all components are installed
rustup component add rustfmt
rustup component add clippy
