/*
 * bn254-c — BN254 precompile demo (EIP-196 / EIP-197).
 *
 * Reads (mode || payload) from read_input.
 *   mode=0: g1_add   (192-byte payload: p1 64 || p2 64; writes 64 bytes)
 *   mode=1: g1_mul   ( 96-byte payload: point 64 || scalar 32; writes 64 bytes)
 *   mode=2: pairing  (num_pairs * (64 + 128) bytes; writes 1 byte verified)
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zkvm_accelerators.h>

extern void read_input(const uint8_t **buf_ptr, size_t *buf_size);
extern void write_output(const uint8_t *output, size_t size);

#define PAIR_SIZE (sizeof(zkvm_bn254_g1_point) + sizeof(zkvm_bn254_g2_point))

int main(void) {
  const uint8_t *buf = 0;
  size_t size = 0;
  read_input(&buf, &size);

  if (size < 1) {
    return 1;
  }

  uint8_t mode = buf[0];
  const uint8_t *payload = buf + 1;
  size_t payload_size = size - 1;
  zkvm_status status;

  if (mode == 0) {
    if (payload_size != 128) {
      return 1;
    }
    zkvm_bn254_g1_point p1, p2, result = {0};
    for (size_t i = 0; i < 64; ++i) {
      p1.data[i] = payload[i];
      p2.data[i] = payload[64 + i];
    }
    status = zkvm_bn254_g1_add(&p1, &p2, &result);
    if (status != ZKVM_EOK) return 1;
    write_output(result.data, sizeof result.data);
  } else if (mode == 1) {
    if (payload_size != 96) {
      return 1;
    }
    zkvm_bn254_g1_point point, result = {0};
    zkvm_bn254_scalar scalar;
    for (size_t i = 0; i < 64; ++i) point.data[i] = payload[i];
    for (size_t i = 0; i < 32; ++i) scalar.data[i] = payload[64 + i];
    status = zkvm_bn254_g1_mul(&point, &scalar, &result);
    if (status != ZKVM_EOK) return 1;
    write_output(result.data, sizeof result.data);
  } else if (mode == 2) {
    if (payload_size % PAIR_SIZE != 0) {
      return 1;
    }
    size_t num_pairs = payload_size / PAIR_SIZE;
    /* SAFETY: the host writes (g1 || g2) pairs concatenated; the struct
     * layout is exactly that (zkvm_bn254_g1_point first, zkvm_bn254_g2_point
     * second, no padding because both are uint8_t arrays). */
    const zkvm_bn254_pairing_pair *pairs = (const zkvm_bn254_pairing_pair *)payload;
    bool verified = false;
    status = zkvm_bn254_pairing(pairs, num_pairs, &verified);
    if (status != ZKVM_EOK) return 1;
    uint8_t out = verified ? 1 : 0;
    write_output(&out, 1);
  } else {
    return 1;
  }

  return 0;
}
