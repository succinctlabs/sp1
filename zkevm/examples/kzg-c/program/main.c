/*
 * kzg-c — KZG point evaluation precompile demo (EIP-4844).
 *
 * Reads a 160-byte input (commitment 48 || z 32 || y 32 || proof 48)
 * from read_input, calls `zkvm_kzg_point_eval`, writes a single byte
 * (0 or 1) via write_output indicating whether the opening verified.
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
  if (size != 48 + 32 + 32 + 48) return 1;

  zkvm_kzg_commitment commitment;
  zkvm_kzg_field_element z;
  zkvm_kzg_field_element y;
  zkvm_kzg_proof proof;
  for (size_t i = 0; i < 48; ++i) commitment.data[i] = buf[i];
  for (size_t i = 0; i < 32; ++i) z.data[i] = buf[48 + i];
  for (size_t i = 0; i < 32; ++i) y.data[i] = buf[48 + 32 + i];
  for (size_t i = 0; i < 48; ++i) proof.data[i] = buf[48 + 32 + 32 + i];

  bool verified = false;
  zkvm_status status = zkvm_kzg_point_eval(&commitment, &z, &y, &proof, &verified);
  if (status != ZKVM_EOK) return 1;

  uint8_t out = verified ? 1u : 0u;
  write_output(&out, 1);
  return 0;
}
