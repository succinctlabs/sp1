/*
 * hello-c — smoke test for the SP1 zkEVM SDK.
 *
 * Reads the (private) input via the standardized read_input(), echoes it
 * back as the (public) output via write_output(), and returns a clean
 * exit code. Linkage:
 *
 *   sdk/libzkevm.a + sdk/zkvm.ld
 *
 * No libc, no compiler-rt — this example is small enough to avoid them.
 */

#include <stddef.h>
#include <stdint.h>

/* From the eth-act IO interface. */
extern void read_input(const uint8_t** buf_ptr, size_t* buf_size);
extern void write_output(const uint8_t* output, size_t size);

int main(void) {
  const uint8_t* in_ptr = 0;
  size_t in_size = 0;
  read_input(&in_ptr, &in_size);

  /* Echo input -> output. The standard says read_input may return
     * (NULL, 0) if no input is provided, in which case we emit a
     * canonical "hello" payload so the verifier still sees something. */
  if (in_size != 0 && in_ptr != 0) {
    write_output(in_ptr, in_size);
  } else {
    static const uint8_t hello[6] = {'h', 'e', 'l', 'l', 'o', '\n'};
    write_output(hello, sizeof hello);
  }

  return 0;
}
