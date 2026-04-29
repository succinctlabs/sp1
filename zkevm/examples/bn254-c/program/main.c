/*
 * bn254-c — BN254 G1 add + scalar mul precompile demo.
 *
 * Reads (mode || payload) from read_input. mode=0: g1_add (128-byte
 * payload p1||p2). mode=1: g1_mul (96-byte payload point||scalar).
 * Writes the 64-byte resulting G1 point.
 */

#include <stddef.h>
#include <stdint.h>

#include <zkvm_accelerators.h>

extern void read_input(const uint8_t **buf_ptr, size_t *buf_size);
extern void write_output(const uint8_t *output, size_t size);

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
  zkvm_bn254_g1_point result = {0};
  zkvm_status status;

  if (mode == 0) {
    if (payload_size != 128) {
      return 1;
    }
    zkvm_bn254_g1_point p1, p2;
    for (size_t i = 0; i < 64; ++i) {
      p1.data[i] = payload[i];
      p2.data[i] = payload[64 + i];
    }
    status = zkvm_bn254_g1_add(&p1, &p2, &result);
  } else if (mode == 1) {
    if (payload_size != 96) {
      return 1;
    }
    zkvm_bn254_g1_point point;
    zkvm_bn254_scalar scalar;
    for (size_t i = 0; i < 64; ++i) point.data[i] = payload[i];
    for (size_t i = 0; i < 32; ++i) scalar.data[i] = payload[64 + i];
    status = zkvm_bn254_g1_mul(&point, &scalar, &result);
  } else {
    return 1;
  }

  if (status != ZKVM_EOK) {
    return 1;
  }

  write_output(result.data, sizeof result.data);
  return 0;
}
