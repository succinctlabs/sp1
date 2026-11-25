#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# Guests and native reference programs have separate Cargo workspaces.
for manifest in \
    Cargo.toml \
    secp256k1/program-v0.29.1/Cargo.toml \
    secp256k1/program-v0.30.0/Cargo.toml \
    secp256k1/native/*/Cargo.toml \
    rustcrypto-bigint/program/Cargo.toml \
    curve25519-dalek/program/Cargo.toml \
    curve25519-dalek-ng/program/Cargo.toml \
    ed25519-consensus/program/Cargo.toml \
    sha/program/Cargo.toml \
    bn/program/Cargo.toml \
    bls12-381/program/Cargo.toml \
    RustCrypto-rsa/program/Cargo.toml \
    ../Cargo.toml \
    ../examples/Cargo.toml \
    ../zkevm/examples/Cargo.toml \
    ../zkevm/libzkevm-cabi/Cargo.toml \
    ../crates/test-artifacts/programs/Cargo.toml
do
    cargo fetch --manifest-path "$manifest"
done
