/**
 * zkVM Cryptographic Accelerators C Interface
 *
 * This header defines the standard C interface for guest programs to access
 * accelerators in zkVMs.
 *
 * Design Notes:
 * - All struct types are sized as multiples of 8 bytes (64-bit word alignment)
 *   for efficient memory operations, as allocating word-aligned data is cheaper
 *   in most zkVM implementations.
 * - Some types (e.g., RIPEMD-160) are zero-padded to achieve this alignment.
 *   Since the EVM also attempts to make all inputs aligned to 256-bits, one does
 *   may not see a difference between the sizes needed for the EVM and the sizes needed here.
 *
 * Usage Notes:
 * - Caller MUST ensure all pointers are valid. If a function is called
 *   with a NULL pointer, the function SHOULD panic.
 * - The caller SHOULD allocate and free the input and output memory.
 */

#ifndef ZKVM_ACCELERATORS_H
#define ZKVM_ACCELERATORS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Return codes
 * ============================================================================ */

/**
 * Status codes returned by zkVM accelerator functions
 *
 * - 0 indicates success
 * - Non-zero indicates failure
 */
typedef enum {
  ZKVM_EOK = 0,   /* Success */
  ZKVM_EFAIL = -1 /* Failure */
} zkvm_status;

/* ============================================================================
 * Type definitions
 * ============================================================================ */

#ifdef __cplusplus
#if __cplusplus >= 201103L
#define ALIGN8 alignas(8)
#else
#error "C++11 or later required for alignment support"
#endif
#elif defined(__STDC_VERSION__)
#if __STDC_VERSION__ >= 201112L
#define ALIGN8 _Alignas(8)
#else
#error "C11 or later required for alignment support"
#endif
#else
#error "Cannot determine language standard; C11 or C++11 required"
#endif

/* Common byte array types */
typedef struct {
  ALIGN8 uint8_t data[16];
} zkvm_bytes_16;

typedef struct {
  ALIGN8 uint8_t data[32];
} zkvm_bytes_32;

typedef struct {
  ALIGN8 uint8_t data[48];
} zkvm_bytes_48;

typedef struct {
  ALIGN8 uint8_t data[64];
} zkvm_bytes_64;

typedef struct {
  ALIGN8 uint8_t data[96];
} zkvm_bytes_96;

typedef struct {
  ALIGN8 uint8_t data[128];
} zkvm_bytes_128;

typedef struct {
  ALIGN8 uint8_t data[192];
} zkvm_bytes_192;

/* Hash types */
typedef zkvm_bytes_32 zkvm_keccak256_hash;
typedef zkvm_bytes_32 zkvm_sha256_hash;
typedef zkvm_bytes_32
    zkvm_ripemd160_hash; /* 20-byte hash padded to 32 bytes, first 12 bytes are zero */

/* secp256k1 types */
typedef zkvm_bytes_32 zkvm_secp256k1_hash;
typedef zkvm_bytes_64 zkvm_secp256k1_signature;
typedef zkvm_bytes_64 zkvm_secp256k1_pubkey;

/* secp256r1 (P-256) types */
typedef zkvm_bytes_32 zkvm_secp256r1_hash;
typedef zkvm_bytes_64 zkvm_secp256r1_signature;
typedef zkvm_bytes_64 zkvm_secp256r1_pubkey;

/* BN254 types */
typedef zkvm_bytes_64 zkvm_bn254_g1_point;
typedef zkvm_bytes_128 zkvm_bn254_g2_point;
typedef zkvm_bytes_32 zkvm_bn254_scalar;

typedef struct {
  zkvm_bn254_g1_point g1;
  zkvm_bn254_g2_point g2;
} zkvm_bn254_pairing_pair;

/* BLS12-381 types */
typedef zkvm_bytes_96 zkvm_bls12_381_g1_point;
typedef zkvm_bytes_192 zkvm_bls12_381_g2_point;
typedef zkvm_bytes_32 zkvm_bls12_381_scalar;

typedef zkvm_bytes_48 zkvm_bls12_381_fp;
typedef zkvm_bytes_96 zkvm_bls12_381_fp2;

typedef struct {
  zkvm_bls12_381_g1_point point;
  zkvm_bls12_381_scalar scalar;
} zkvm_bls12_381_g1_msm_pair;

typedef struct {
  zkvm_bls12_381_g2_point point;
  zkvm_bls12_381_scalar scalar;
} zkvm_bls12_381_g2_msm_pair;

typedef struct {
  zkvm_bls12_381_g1_point g1;
  zkvm_bls12_381_g2_point g2;
} zkvm_bls12_381_pairing_pair;

/* BLAKE2f types */
typedef zkvm_bytes_64 zkvm_blake2f_state;
typedef zkvm_bytes_128 zkvm_blake2f_message;
typedef zkvm_bytes_16 zkvm_blake2f_offset;

/* KZG types */
typedef zkvm_bytes_48 zkvm_kzg_commitment;
typedef zkvm_bytes_48 zkvm_kzg_proof;
typedef zkvm_bytes_32 zkvm_kzg_field_element;

/* ============================================================================
 * Non-Precompile Functions
 * ============================================================================ */

/**
 * Compute Keccak-256 hash
 *
 * @param data Pointer to input data
 * @param len Length of input data in bytes
 * @param[out] output Pointer to output hash
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_keccak256(const uint8_t* data, size_t len,
                           zkvm_keccak256_hash* output);

/**
 * secp256k1 signature verification
 *
 * Verifies an ECDSA signature on the secp256k1 curve.
 *
 * @param msg Pointer to message hash
 * @param sig Pointer to signature (r || s)
 * @param pubkey Pointer to uncompressed public key (x || y)
 * @param[out] verified Pointer to bool indicating if signature is valid
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_secp256k1_verify(const zkvm_secp256k1_hash* msg,
                                  const zkvm_secp256k1_signature* sig,
                                  const zkvm_secp256k1_pubkey* pubkey,
                                  bool* verified);

/* ============================================================================
 * Ethereum Precompiles
 *
 * Note: These methods may not have the same API as the EVM precompiles because
 * in most cases, we care about the raw underlying cryptographic primitive.
 * ============================================================================ */

/**
 * ECRECOVER - Recover public key from signature
 *
 * Precompile: 0x01
 *
 * Implements ecrecover precompile for secp256k1 signature recovery.
 * Note: The function as defined on the Ethereum layer returns an address.
 * We return a public key and the user will need to call Keccak manually.
 *
 *
 * @param msg Pointer to message hash
 * @param sig Pointer to signature (r || s)
 * @param recid Recovery ID
 * @param[out] output Pointer to output buffer (public key)
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_secp256k1_ecrecover(const zkvm_secp256k1_hash* msg,
                                     const zkvm_secp256k1_signature* sig,
                                     uint8_t recid,
                                     zkvm_secp256k1_pubkey* output);

/**
 * Compute SHA-256 hash
 *
 * Precompile: 0x02
 *
 * @param data Pointer to input data
 * @param len Length of input data in bytes
 * @param[out] output Pointer to output hash
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_sha256(const uint8_t* data, size_t len,
                        zkvm_sha256_hash* output);

/**
 * Compute RIPEMD-160 hash
 *
 * Precompile: 0x03
 *
 * @param data Pointer to input data
 * @param len Length of input data in bytes
 * @param[out] output Pointer to output hash (20 bytes of hash, first 12 bytes zero-padded)
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_ripemd160(const uint8_t* data, size_t len,
                           zkvm_ripemd160_hash* output);

/**
 * The Identity/datacopy function is not provided as it can be implemented
 * in the guest program efficiently.
 *
 * Precompile: 0x04
 */

/**
 * Modular exponentiation
 *
 * Precompile: 0x05
 *
 * Computes (base^exp) % modulus for arbitrary precision integers.
 *
 * @param base Pointer to base value bytes
 * @param base_len Length of base in bytes
 * @param exp Pointer to exponent bytes
 * @param exp_len Length of exponent in bytes
 * @param modulus Pointer to modulus bytes
 * @param mod_len Length of modulus in bytes
 * @param[out] output Pointer to output buffer (must be exactly mod_len bytes)
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_modexp(const uint8_t* base, size_t base_len,
                        const uint8_t* exp, size_t exp_len,
                        const uint8_t* modulus, size_t mod_len,
                        uint8_t* output);

/**
 * BN254 G1 point addition
 *
 * Precompile: 0x06
 * EIP-196
 *
 * @param p1 Pointer to first point (x || y)
 * @param p2 Pointer to second point (x || y)
 * @param[out] result Pointer to output point (x || y)
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_bn254_g1_add(const zkvm_bn254_g1_point* p1,
                              const zkvm_bn254_g1_point* p2,
                              zkvm_bn254_g1_point* result);

/**
 * BN254 G1 scalar multiplication
 *
 * Precompile: 0x07
 * EIP-196
 *
 * @param point Pointer to input point (x || y)
 * @param scalar Pointer to scalar
 * @param[out] result Pointer to output point (x || y)
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_bn254_g1_mul(const zkvm_bn254_g1_point* point,
                              const zkvm_bn254_scalar* scalar,
                              zkvm_bn254_g1_point* result);

/**
 * BN254 pairing check
 *
 * Precompile: 0x08
 * EIP-197
 *
 * Checks if the pairing equation holds for the given points.
 *
 * @param pairs Array of G1-G2 point pairs
 * @param num_pairs Number of point pairs
 * @param[out] verified Pointer to bool indicating if pairing check passes
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_bn254_pairing(const zkvm_bn254_pairing_pair* pairs,
                               size_t num_pairs, bool* verified);

/**
 * BLAKE2f compression function
 *
 * Precompile: 0x09
 * EIP-152
 *
 * Implements the BLAKE2 compression function F.
 *
 * BLAKE2f is highly performance-sensitive and often used in tight loops for hashing.
 * The in-place update design minimizes memory allocations and copies.
 *
 * @param rounds Number of rounds (uint32, big-endian)
 * @param[in,out] h Pointer to state vector (8 × uint64 little-endian).
 *                   Input: initial state. Output: updated state after compression.
 * @param m Pointer to message block (16 × uint64 little-endian)
 * @param t Pointer to offset counters (2 × uint64 little-endian)
 * @param f Final block indicator (1 byte: 0x00 or 0x01)
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 *
 * @remark The use of big-endian encoding for the rounds parameter matches the specification in EIP-152.
 */
zkvm_status zkvm_blake2f(uint32_t rounds, zkvm_blake2f_state* h,
                         const zkvm_blake2f_message* m,
                         const zkvm_blake2f_offset* t, uint8_t f);

/**
 * Point evaluation precompile
 *
 * Precompile: 0x0a
 * EIP-4844
 *
 * Verifies a KZG proof for point evaluation.
 *
 * @param commitment Pointer to KZG commitment
 * @param z Pointer to evaluation point
 * @param y Pointer to claimed evaluation
 * @param proof Pointer to KZG proof
 * @param[out] verified Pointer to bool indicating if proof is valid
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_kzg_point_eval(const zkvm_kzg_commitment* commitment,
                                const zkvm_kzg_field_element* z,
                                const zkvm_kzg_field_element* y,
                                const zkvm_kzg_proof* proof, bool* verified);

/**
 * BLS12-381 G1 point addition
 *
 * Precompile: 0x0b
 * EIP-2537
 *
 * @param p1 Pointer to first G1 point (Fp x, Fp y)
 * @param p2 Pointer to second G1 point (Fp x, Fp y)
 * @param[out] result Pointer to output G1 point
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_bls12_g1_add(const zkvm_bls12_381_g1_point* p1,
                              const zkvm_bls12_381_g1_point* p2,
                              zkvm_bls12_381_g1_point* result);

/**
 * BLS12-381 G1 multi-scalar multiplication
 *
 * Precompile: 0x0c
 * EIP-2537
 *
 * @param pairs Pointer to array of point-scalar pairs
 * @param num_pairs Number of point-scalar pairs
 * @param[out] result Pointer to output G1 point
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_bls12_g1_msm(const zkvm_bls12_381_g1_msm_pair* pairs,
                              size_t num_pairs,
                              zkvm_bls12_381_g1_point* result);

/**
 * BLS12-381 G2 point addition
 *
 * Precompile: 0x0d
 * EIP-2537
 *
 * @param p1 Pointer to first G2 point (Fp2 x, Fp2 y)
 * @param p2 Pointer to second G2 point (Fp2 x, Fp2 y)
 * @param[out] result Pointer to output G2 point
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_bls12_g2_add(const zkvm_bls12_381_g2_point* p1,
                              const zkvm_bls12_381_g2_point* p2,
                              zkvm_bls12_381_g2_point* result);

/**
 * BLS12-381 G2 multi-scalar multiplication
 *
 * Precompile: 0x0e
 * EIP-2537
 *
 * @param pairs Pointer to array of point-scalar pairs
 * @param num_pairs Number of point-scalar pairs
 * @param[out] result Pointer to output G2 point
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_bls12_g2_msm(const zkvm_bls12_381_g2_msm_pair* pairs,
                              size_t num_pairs,
                              zkvm_bls12_381_g2_point* result);

/**
 * BLS12-381 pairing check
 *
 * Precompile: 0x0f
 * EIP-2537
 *
 * @param pairs Array of G1-G2 point pairs
 * @param num_pairs Number of point pairs
 * @param[out] verified Pointer to bool indicating if pairing check passes
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_bls12_pairing(const zkvm_bls12_381_pairing_pair* pairs,
                               size_t num_pairs, bool* verified);

/**
 * BLS12-381 map Fp to G1
 *
 * Precompile: 0x10
 * EIP-2537
 *
 * @param field_element Pointer to Fp element
 * @param[out] result Pointer to output G1 point
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_bls12_map_fp_to_g1(const zkvm_bls12_381_fp* field_element,
                                    zkvm_bls12_381_g1_point* result);

/**
 * BLS12-381 map Fp2 to G2
 *
 * Precompile: 0x11
 * EIP-2537
 *
 * @param field_element Pointer to Fp2 element
 * @param[out] result Pointer to output G2 point
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_bls12_map_fp2_to_g2(const zkvm_bls12_381_fp2* field_element,
                                     zkvm_bls12_381_g2_point* result);

/**
 * secp256r1 (P-256) signature verification
 *
 * Precompile: 0x100
 * EIP-7212
 *
 * @param msg Pointer to message hash
 * @param sig Pointer to signature (r || s)
 * @param pubkey Pointer to uncompressed public key (x || y)
 * @param[out] verified Pointer to bool indicating if signature is valid
 * @return ZKVM_EOK on success, ZKVM_EFAIL on failure
 */
zkvm_status zkvm_secp256r1_verify(const zkvm_secp256r1_hash* msg,
                                  const zkvm_secp256r1_signature* sig,
                                  const zkvm_secp256r1_pubkey* pubkey,
                                  bool* verified);

#ifdef __cplusplus
}
#endif

#endif /* ZKVM_ACCELERATORS_H */
