/*
 * panic-c — failed-termination showcase, C edition.
 *
 * Reads a single byte; if non-zero, calls `abort()` (which libzkevm
 * routes to `zkvm_halt(1)`). Otherwise writes "no panic\n" and exits
 * cleanly. Mirror of the Rust `panic` example.
 */

#include <stddef.h>
#include <stdint.h>

extern void read_input(const uint8_t **buf_ptr, size_t *buf_size);
extern void write_output(const uint8_t *output, size_t size);
extern void abort(void) __attribute__((noreturn));

int main(void) {
  const uint8_t *buf = 0;
  size_t size = 0;
  read_input(&buf, &size);

  uint8_t flag = (size >= 1 && buf != 0) ? buf[0] : 0;

  if (flag != 0) {
    abort();
  }

  static const uint8_t ok[9] = {'n', 'o', ' ', 'p', 'a', 'n', 'i', 'c', '\n'};
  write_output(ok, sizeof ok);
  return 0;
}
