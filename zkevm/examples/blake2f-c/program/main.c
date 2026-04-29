/*
 * blake2f-c — BLAKE2f (EIP-152) precompile demo, C edition.
 *
 * Reads an EIP-152-shaped input (213 bytes: 4-byte BE rounds + 64-byte h +
 * 128-byte m + 16-byte t + 1-byte f) from read_input, calls
 * `zkvm_blake2f`, and writes the 64-byte updated state via write_output.
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

  if (size != 4 + 64 + 128 + 16 + 1) {
    return 1;
  }

  uint32_t rounds = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
                    ((uint32_t)buf[2] << 8) | (uint32_t)buf[3];

  zkvm_blake2f_state h;
  zkvm_blake2f_message m;
  zkvm_blake2f_offset t;

  /* `read_input` returns a pointer into shared memory; we copy into the
   * 8-byte-aligned struct types so the precompile sees the right layout. */
  for (size_t i = 0; i < sizeof h.data; ++i) h.data[i] = buf[4 + i];
  for (size_t i = 0; i < sizeof m.data; ++i) m.data[i] = buf[4 + 64 + i];
  for (size_t i = 0; i < sizeof t.data; ++i) t.data[i] = buf[4 + 64 + 128 + i];
  uint8_t f = buf[4 + 64 + 128 + 16];

  zkvm_status status = zkvm_blake2f(rounds, &h, &m, &t, f);
  if (status != ZKVM_EOK) {
    return 1;
  }

  write_output(h.data, sizeof h.data);
  return 0;
}
