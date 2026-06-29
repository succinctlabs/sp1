/*
 * Minimal C guest for SP1 / zkVM-standards.
 *
 * Reads an input via the eth-act IO interface, runs your logic on it,
 * writes the public output. Fill in the body of `main`.
 */

#include <stddef.h>
#include <stdint.h>

#include <zkvm_accelerators.h>

/* eth-act IO interface — see standards/io-interface/README.md. */
extern void read_input(const uint8_t **buf_ptr, size_t *buf_size);
extern void write_output(const uint8_t *output, size_t size);

int main(void) {
  /* Pull the (private) input — the host must push it as a single chunk
   * via `stdin.write_slice(...)`. See libzkevm/src/io.rs for the full
   * host-side contract. */
  const uint8_t *input = 0;
  size_t input_size = 0;
  read_input(&input, &input_size);

  /* ============ YOUR LOGIC HERE ============ *
   *
   * Examples:
   *
   *   Hash the input:
   *     zkvm_keccak256_hash digest;
   *     zkvm_keccak256(input, input_size, &digest);
   *     write_output(digest.data, sizeof digest.data);
   *
   *   Echo:
   *     write_output(input, input_size);
   *
   *   Signal failure (return non-zero exit code):
   *     return 42;
   *
   * ========================================== */

  write_output(input, input_size);
  return 0;
}
