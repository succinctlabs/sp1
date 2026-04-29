/*
 * assert-c — failed-termination via standard `<assert.h>`.
 *
 * Reads a single byte; if non-zero, fires `assert(0)`, which expands to
 * a call into glibc-shape `__assert_fail`. libzkevm's shim routes that
 * to `zkvm_halt(1)`, the same exit code path as `abort()`. Otherwise
 * writes "no panic\n" and exits cleanly.
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

extern void read_input(const uint8_t **buf_ptr, size_t *buf_size);
extern void write_output(const uint8_t *output, size_t size);

int main(void) {
  const uint8_t *buf = 0;
  size_t size = 0;
  read_input(&buf, &size);

  uint8_t flag = (size >= 1 && buf != 0) ? buf[0] : 0;

  assert(flag == 0);

  static const uint8_t ok[9] = {'n', 'o', ' ', 'p', 'a', 'n', 'i', 'c', '\n'};
  write_output(ok, sizeof ok);
  return 0;
}
