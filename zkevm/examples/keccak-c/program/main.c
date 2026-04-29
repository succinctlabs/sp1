/*
 * keccak-c — first non-stub precompile demo, C edition.
 *
 * Reads bytes via read_input, computes keccak256 via libzkevm's
 * `zkvm_keccak256`, writes the 32-byte digest via write_output.
 * Mirror of the Rust `keccak` example.
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

  zkvm_keccak256_hash digest;
  zkvm_status status = zkvm_keccak256(buf, size, &digest);
  if (status != ZKVM_EOK) {
    return 1;
  }

  write_output(digest.data, sizeof digest.data);
  return 0;
}
