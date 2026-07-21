# [DRAFT — for review, do not file as-is] Proposed issue for eth-act/zkvm-standards

**Title:** c-interface-accelerators: point encodings and per-operation validation rules are underspecified — two conforming implementations can disagree

## Summary

`standards/c-interface-accelerators/zkvm_accelerators.h` pins down struct sizes and
function signatures, but not the byte-level interpretation of the curve-point structs or
the validation each operation must perform. As a result, two zkVMs can both implement the
header faithfully and still return different results (or different success/failure status)
for the same guest program — which defeats the standard's portability goal.

We hit each of these while implementing the interface for SP1 (succinctlabs/sp1, `zkevm/`
platform); concrete questions below.

## 1. BLS12-381 point encoding is not specified

For `zkvm_bls12_381_g1_point` (96 bytes) and `zkvm_bls12_381_g2_point` (192 bytes) the
header says only "Fp x, Fp y" / "Fp2 x, Fp2 y". Unspecified:

* **Fp2 coefficient order** — `c0 || c1` (EIP-2537 wire order) or `c1 || c0`
  (zkcrypto/blst `to_uncompressed()` order)? Implementations wrapping a serialization
  library will naturally pick the latter; implementations transcribing EIP-2537 will pick
  the former. Same guest bytes, different G2 point.
* **Point at infinity** — all-zero bytes (EIP-2537) or a flag bit in the leading byte
  (zkcrypto sets `0x40`, which in the all-zeros convention is an *invalid* non-zero
  x-coordinate)? These are mutually incompatible: each convention's infinity is the other
  convention's decode error.
* **Byte order of Fp** — presumably 48-byte big-endian, but it should be stated.
* **Scalar interpretation** — 32 bytes big-endian, and is a value ≥ the group order an
  error or reduced?

The same questions apply to the BN254 structs (64/128-byte points): EIP-196/197 use
big-endian `x || y` with all-zeros infinity, and G2 coefficients in the order
`x_imag || x_real || y_imag || y_real` — should the struct match?

**Suggestion:** specify byte-exact encodings in the header comments. Aligning with the
EIP-2537 / EIP-196 wire formats (minus the 64→48-byte padding for BLS Fp) would let the
official Ethereum precompile test vectors be applied to this interface with a trivial,
mechanical transform, and makes the EVM-client glue thinner.

## 2. Per-operation validation rules are not specified

The functions are annotated with their precompile numbers ("Precompile: 0x0b, EIP-2537"),
which suggests EIP semantics, but the EIPs prescribe *different* validation per operation:

* EIP-2537 **G1ADD/G2ADD**: field validation + on-curve check, **no subgroup check**
  (deliberately dropped to keep ADD cheap; the official vectors include on-curve,
  non-subgroup inputs that must succeed).
* EIP-2537 **MSM and PAIRING**: subgroup check **required**.
* `MAP_FP_TO_G1`/`MAP_FP2_TO_G2`: input must be a canonical field element (< p), reject
  otherwise.

Is an implementation required to follow these exactly? If yes, a sentence per function
("validates X, does not validate Y; returns ZKVM_EFAIL on Z") would make conformance
testable. If no — i.e. the "simplified, raw cryptographic operations" reading — then the
guest-side EVM glue must do its own validation, and that should be stated explicitly so
implementations don't add divergent checks. (We initially shipped subgroup checks on ADD;
another implementation reasonably might not. Same header, consensus-relevant divergence.)

Related: for `zkvm_secp256k1_ecrecover`, is `ZKVM_EFAIL` the intended return for a
well-formed call whose signature is simply unrecoverable (the EVM "return empty output"
case), with callers expected to map EFAIL → empty? A sentence in the header would prevent
guests from treating EFAIL as a trap condition.

## 3. blake2f `rounds` comment is self-contradictory

```c
 * @param rounds Number of rounds (uint32, big-endian)
```

A by-value `uint32_t` has no endianness at the call boundary. Presumably this means "the
EVM input encodes rounds as 4 big-endian bytes; parse it into a native uint32 before
calling" — but as written, an implementer could plausibly byte-swap. Suggest rewording to
"number of rounds (native integer; note the EIP-152 input encodes this as 4 big-endian
bytes, which the caller must parse)".

## 4. Conformance vectors

Would you take a PR adding a `test-vectors/` directory (or a pointer to the official
EIP-2537/196/197/152 + Wycheproof + KZG suites with the transform rules from wire format
to these structs)? Once encodings and validation rules are fixed (points 1–2), a shared
vector suite is what actually keeps N implementations interoperable.

We're happy to contribute the encoding spec text and the vector transform from our
implementation once the intended conventions are confirmed.
