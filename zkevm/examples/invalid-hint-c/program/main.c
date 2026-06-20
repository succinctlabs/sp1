/*
 * invalid-hint-c — demonstrates `zkvm_invalid_hint()` and exit code 3.
 *
 * Reads a single byte. If non-zero, calls `zkvm_invalid_hint()` which
 * halts the guest with exit code 3 (`StatusCode::INVALID_HINT`). The
 * patched crypto crates use the same primitive when a prover-supplied
 * hint fails verification — exit 3 disambiguates it from a regular
 * failure exit (1) so a malicious prover cannot forge a panic by
 * feeding wrong hints.
 *
 * If the byte is zero, the program writes "ok\n" and returns 0.
 */

#include <stddef.h>
#include <stdint.h>

extern void read_input(const uint8_t **buf_ptr, size_t *buf_size);
extern void write_output(const uint8_t *output, size_t size);
extern __attribute__((noreturn)) void zkvm_invalid_hint(void);

int main(void) {
  const uint8_t *buf = 0;
  size_t size = 0;
  read_input(&buf, &size);

  uint8_t flag = (size >= 1 && buf != 0) ? buf[0] : 0;

  if (flag != 0) {
    zkvm_invalid_hint();
  }

  static const uint8_t ok[3] = {'o', 'k', '\n'};
  write_output(ok, sizeof ok);
  return 0;
}
