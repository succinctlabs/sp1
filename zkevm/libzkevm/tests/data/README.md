# Vendored conformance test vectors

Official test-vector suites, vendored wholesale (never sampled) and
version-pinned. Consumed by `tests/conformance/`.

| Directory | Source | License | Pinned at |
|---|---|---|---|
| `geth/` | [go-ethereum `core/vm/testdata/precompiles`](https://github.com/ethereum/go-ethereum/tree/master/core/vm/testdata/precompiles) | LGPL-3.0 (test data, unmodified) | `geth/GETH_COMMIT.txt` |
| `wycheproof/` | [C2SP/wycheproof `testvectors_v1`](https://github.com/C2SP/wycheproof) | Apache-2.0 | `wycheproof/WYCHEPROOF_COMMIT.txt` |

To refresh: re-run the download with a new commit hash and update the
corresponding `*_COMMIT.txt`. Files must be committed unmodified so they
can be diffed against upstream.

Coverage notes:

* `geth/` covers EIP-2537 (BLS12-381, incl. all `fail-*` rejection
  vectors), EIP-196/197 (BN254), ecrecover, EIP-198/2565/7883 (modexp),
  EIP-152 (blake2f), EIP-4844 point evaluation, and EIP-7951 (p256verify).
* `wycheproof/` covers ECDSA verify for secp256k1 and secp256r1
  (SHA-256), including the adversarial DER/BER and boundary cases.
* KZG beyond the geth `pointEvaluation` vectors is intentionally not
  vendored: `kzg-rs` runs the full official `verify_kzg_proof` suite
  upstream, and `zkvm_kzg_point_eval` is a thin wrapper over it. The
  sampled YAML fixtures in `zkevm/examples/fixtures/data/kzg/` cover the
  end-to-end path.
