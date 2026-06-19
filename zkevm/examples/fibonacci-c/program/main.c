/*
 * fibonacci-c — C version of the Rust fibonacci example.
 *
 * Reads a u32 n (4 bytes LE) via read_input, computes fib(n) % 7919
 * iteratively, writes the 4-byte u32 result via write_output.
 *
 * Demonstrates that the same arithmetic + IO shape works from C
 * through libzkevm's extern "C" surface.
 */

#include <stddef.h>
#include <stdint.h>

extern void read_input(const uint8_t **buf_ptr, size_t *buf_size);
extern void write_output(const uint8_t *output, size_t size);

int main(void) {
  const uint8_t *buf = 0;
  size_t size = 0;
  read_input(&buf, &size);

  uint32_t n = 0;
  if (size >= 4 && buf != 0) {
    n = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) | ((uint32_t)buf[2] << 16) |
        ((uint32_t)buf[3] << 24);
  }

  uint32_t a = 0, b = 1;
  for (uint32_t i = 0; i < n; ++i) {
    uint32_t c = (a + b) % 7919u;
    a = b;
    b = c;
  }

  uint8_t out[4] = {(uint8_t)(a & 0xff), (uint8_t)((a >> 8) & 0xff),
                   (uint8_t)((a >> 16) & 0xff), (uint8_t)((a >> 24) & 0xff)};
  write_output(out, sizeof out);
  return 0;
}
