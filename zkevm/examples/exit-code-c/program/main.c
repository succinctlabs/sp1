/*
 * exit-code-c — failed termination via plain `return 1` from `main`.
 *
 * Reads a single byte. If non-zero, returns 1; the SP1 entrypoint
 * forwards `main`'s i32 return value to `syscall_halt`, so the guest
 * halts with exit code 1 (failed termination per the standard) without
 * an explicit `abort()` or `assert()` call. Otherwise writes
 * "no panic\n" and returns 0.
 */

#include <stddef.h>
#include <stdint.h>

extern void read_input(const uint8_t **buf_ptr, size_t *buf_size);
extern void write_output(const uint8_t *output, size_t size);

int main(void) {
  const uint8_t *buf = 0;
  size_t size = 0;
  read_input(&buf, &size);

  uint8_t flag = (size >= 1 && buf != 0) ? buf[0] : 0;

  if (flag != 0) {
    return 1;
  }

  static const uint8_t ok[9] = {'n', 'o', ' ', 'p', 'a', 'n', 'i', 'c', '\n'};
  write_output(ok, sizeof ok);
  return 0;
}
