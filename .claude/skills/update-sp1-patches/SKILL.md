---
name: update-sp1-patches
description: Update sp1-patches git repos when releasing a new SP1 version. Use when bumping SP1 version and need to update patched crypto crates.
allowed-tools: Read, Grep, Glob, Bash, Edit, Write
argument-hint: [OLD_VERSION] [NEW_VERSION]
---

# Update SP1 Patches for New Version

Update all patched crates from SP1 version `$0` to `$1`.

## Context

SP1 maintains patched versions of cryptographic crates in the `sp1-patches` GitHub organization. These patches:
- Depend on `sp1-lib` from crates.io
- Are referenced via git tags in Cargo.toml files
- Follow the naming convention: `patch-[CRATE]-[VERSION]-sp1-[SP1_VERSION]`

When releasing a new SP1 version, patches must be updated so their `sp1-lib` dependency matches.

## Step 1: Identify Current Patches

Find all patch references in the codebase:

```bash
grep -r "sp1-patches" --include="*.toml" . | grep -v target | grep "tag ="
```

Key locations:
- `patch-testing/Cargo.toml` - Main patch testing workspace
- `patch-testing/*/program/Cargo.toml` - Individual program tests
- `examples/Cargo.toml` - Example programs
- `crates/test-artifacts/programs/*/Cargo.toml` - Test artifacts
- `crates/verifier/guest-verify-programs/Cargo.toml` - Verifier programs

## Step 2: Categorize Repositories

**Repos WITH sp1-lib dependency** (need version update):
- `curve25519-dalek` - Ed25519 curve operations
- `curve25519-dalek-ng` - Ed25519 (ng version)
- `tiny-keccak` - Keccak hashing
- `bn` (substrate-bn) - BN254 pairing
- `bls12_381` - BLS12-381 pairing
- `RustCrypto-RSA` - RSA operations
- `elliptic-curves` (k256, p256) - ECDSA operations

**Repos with TRANSITIVE sp1-lib dependency**:
- `rust-secp256k1` - depends on `k256` from elliptic-curves

**Repos WITHOUT sp1-lib** (create alias tags):
- `RustCrypto-hashes` - SHA2, SHA3 patches
- `RustCrypto-bigint` - BigInt operations

## Step 3: Update Process

### For repos WITH sp1-lib:

```bash
cd /tmp/sp1-patches-update
git clone git@github.com:sp1-patches/<REPO>.git
cd <REPO>

# Checkout old tag
git checkout patch-<CRATE_VERSION>-sp1-<OLD_SP1_VERSION>
git checkout -b temp-update-branch

# Find and update sp1-lib version (check format first!)
grep -r "sp1-lib" --include="Cargo.toml" .

# Update (adjust sed pattern based on format found):
# For: sp1-lib = "X.Y.Z"
sed -i 's/sp1-lib = "<OLD_VERSION>"/sp1-lib = "<NEW_VERSION>"/g' */Cargo.toml Cargo.toml

# For: sp1-lib = { version = "X.Y.Z", ... }
sed -i 's/sp1-lib = { version = "<OLD_VERSION>"/sp1-lib = { version = "<NEW_VERSION>"/g' */Cargo.toml Cargo.toml

# Commit and create new tag
git add -A
git commit -m "Update sp1-lib dependency to <NEW_VERSION>"
git tag patch-<CRATE_VERSION>-sp1-<NEW_SP1_VERSION>
git push origin patch-<CRATE_VERSION>-sp1-<NEW_SP1_VERSION>
```

### For repos with TRANSITIVE dependencies (rust-secp256k1):

Also update references to other sp1-patches repos:
```bash
# Update k256 dependency tag
sed -i 's/patch-k256-13.4-sp1-<OLD>/patch-k256-13.4-sp1-<NEW>/g' Cargo.toml
```

### For repos WITHOUT sp1-lib (alias tags):

```bash
git checkout patch-<CRATE_VERSION>-sp1-<OLD_SP1_VERSION>
git tag patch-<CRATE_VERSION>-sp1-<NEW_SP1_VERSION>
git push origin patch-<CRATE_VERSION>-sp1-<NEW_SP1_VERSION>
```

## Step 4: Update Local Cargo.toml Files

```bash
# Find all files with old tags
find . -name "Cargo.toml" -exec grep -l "sp1-<OLD_VERSION>\"" {} \;

# Update all occurrences
find . -name "Cargo.toml" -exec sed -i 's/-sp1-<OLD_VERSION>"/-sp1-<NEW_VERSION>"/g' {} \;
```

## Step 5: Verify

```bash
# Check tags exist on GitHub
gh api repos/sp1-patches/<REPO>/git/refs/tags/patch-<VERSION>-sp1-<NEW> --jq '.ref'

# Build to verify resolution
cd patch-testing && cargo check

# Ensure no old tags remain
grep -r "sp1-<OLD_VERSION>\"" --include="*.toml" . | grep -v target
```

## Tag Reference

| Repository | Tag Pattern | Has sp1-lib |
|------------|-------------|-------------|
| RustCrypto-hashes | patch-sha2-X.Y.Z-sp1-V, patch-sha3-X.Y.Z-sp1-V | No |
| RustCrypto-bigint | patch-X.Y.Z-sp1-V | No |
| tiny-keccak | patch-X.Y.Z-sp1-V | Yes |
| curve25519-dalek | patch-X.Y.Z-sp1-V | Yes |
| curve25519-dalek-ng | patch-X.Y.Z-sp1-V | Yes |
| rust-secp256k1 | patch-X.Y.Z-sp1-V | No (transitive via k256) |
| bn | patch-X.Y.Z-sp1-V | Yes |
| bls12_381 | patch-X.Y.Z-sp1-V | Yes |
| RustCrypto-RSA | patch-X.Y.Z-sp1-V | Yes |
| elliptic-curves | patch-k256-X.Y.Z-sp1-V, patch-p256-X.Y.Z-sp1-V | Yes |

## Important Notes

- **Never overwrite existing tags** - always create new tags
- **Check sp1-lib format** before sed replacement (simple string vs table format)
- **Update transitive deps first** - elliptic-curves before rust-secp256k1
- **Verify with cargo check** - ensures all dependencies resolve correctly
