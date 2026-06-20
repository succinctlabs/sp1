#!/usr/bin/env bash
# Download/refresh the vendored conformance vectors, pinned to upstream
# commits (recorded in */[A-Z]*_COMMIT.txt). See README.md.
set -euo pipefail
cd "$(dirname "$0")"

GETH_SHA=${GETH_SHA:-$(gh api repos/ethereum/go-ethereum/commits/master --jq '.sha')}
echo "geth pinned at $GETH_SHA"
mkdir -p geth wycheproof
cd geth
FILES="blsG1Add blsG1Mul blsG1MultiExp blsG2Add blsG2Mul blsG2MultiExp blsPairing blsMapG1 blsMapG2 fail-blsG1Add fail-blsG1Mul fail-blsG1MultiExp fail-blsG2Add fail-blsG2Mul fail-blsG2MultiExp fail-blsPairing fail-blsMapG1 fail-blsMapG2 bn256Add bn256ScalarMul bn256Pairing ecRecover modexp modexp_eip2565 modexp_eip7883 blake2F fail-blake2f p256Verify pointEvaluation"
for f in $FILES; do
  curl -sf "https://raw.githubusercontent.com/ethereum/go-ethereum/$GETH_SHA/core/vm/testdata/precompiles/$f.json" -o "$f.json" \
    || echo "MISSING: $f"
done
echo "$GETH_SHA" > GETH_COMMIT.txt
echo "geth files: $(ls -- *.json | wc -l), size: $(du -sh . | cut -f1)"

cd ../wycheproof
WP_SHA=${WP_SHA:-$(gh api repos/C2SP/wycheproof/commits/main --jq '.sha' 2>/dev/null || gh api repos/C2SP/wycheproof/commits/master --jq '.sha')}
echo "wycheproof pinned at $WP_SHA"
for f in ecdsa_secp256k1_sha256_test ecdsa_secp256r1_sha256_test; do
  curl -sf "https://raw.githubusercontent.com/C2SP/wycheproof/$WP_SHA/testvectors_v1/$f.json" -o "$f.json" \
    || echo "MISSING: $f"
done
echo "$WP_SHA" > WYCHEPROOF_COMMIT.txt
echo "wycheproof files: $(ls -- *.json | wc -l), size: $(du -sh . | cut -f1)"
