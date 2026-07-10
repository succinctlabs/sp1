/*
 * ripemd-c — RIPEMD-160 precompile demo, C edition.
 *
 * Reads bytes via read_input, computes RIPEMD-160 via libzkevm's
 * `zkvm_ripemd160`, writes the 32-byte output (20-byte digest +
 * 12-byte zero pad, per `zkvm_accelerators.h`) via write_output.
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

  zkvm_ripemd160_hash digest;
  zkvm_status status = zkvm_ripemd160(buf, size, &digest);
  if (status != ZKVM_EOK) {
    return 1;
  }

  write_output(digest.data, sizeof digest.data);
  return 0;
}
