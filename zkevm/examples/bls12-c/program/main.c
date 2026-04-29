/*
 * bls12-c — BLS12-381 ops precompile demo (EIP-2537).
 *
 * Mode 0: g1_add — input 192 bytes (p1 96 || p2 96), output 96 bytes.
 * Mode 1: g2_add — input 384 bytes (p1 192 || p2 192), output 192 bytes.
 * Mode 2: pairing — input num_pairs * (96 + 192) bytes after the mode
 *          byte, output 1 byte (verified).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zkvm_accelerators.h>

extern void read_input(const uint8_t **buf_ptr, size_t *buf_size);
extern void write_output(const uint8_t *output, size_t size);

int main(void) {
  const uint8_t *buf = 0;
  size_t size = 0;
  read_input(&buf, &size);
  if (size < 1) return 1;

  uint8_t mode = buf[0];
  const uint8_t *payload = buf + 1;
  size_t payload_size = size - 1;
  zkvm_status status;

  if (mode == 0) {
    if (payload_size != 192) return 1;
    zkvm_bls12_381_g1_point p1, p2, result = {0};
    for (size_t i = 0; i < 96; ++i) {
      p1.data[i] = payload[i];
      p2.data[i] = payload[96 + i];
    }
    status = zkvm_bls12_g1_add(&p1, &p2, &result);
    if (status != ZKVM_EOK) return 1;
    write_output(result.data, sizeof result.data);
  } else if (mode == 1) {
    if (payload_size != 384) return 1;
    zkvm_bls12_381_g2_point p1, p2, result = {0};
    for (size_t i = 0; i < 192; ++i) {
      p1.data[i] = payload[i];
      p2.data[i] = payload[192 + i];
    }
    status = zkvm_bls12_g2_add(&p1, &p2, &result);
    if (status != ZKVM_EOK) return 1;
    write_output(result.data, sizeof result.data);
  } else if (mode == 2) {
    if (payload_size % (96 + 192) != 0) return 1;
    size_t num_pairs = payload_size / (96 + 192);
    /* Build the pair array on the stack — bounded by host ABI agreement. */
    if (num_pairs > 16) return 1;
    zkvm_bls12_381_pairing_pair pairs[16];
    for (size_t i = 0; i < num_pairs; ++i) {
      const uint8_t *p = payload + i * (96 + 192);
      for (size_t j = 0; j < 96; ++j) pairs[i].g1.data[j] = p[j];
      for (size_t j = 0; j < 192; ++j) pairs[i].g2.data[j] = p[96 + j];
    }
    bool verified = false;
    status = zkvm_bls12_pairing(pairs, num_pairs, &verified);
    if (status != ZKVM_EOK) return 1;
    uint8_t out = verified ? 1u : 0u;
    write_output(&out, 1);
  } else {
    return 1;
  }
  return 0;
}
