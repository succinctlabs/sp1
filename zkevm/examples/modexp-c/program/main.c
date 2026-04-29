/*
 * modexp-c — EIP-198 modexp precompile demo, C edition.
 *
 * Reads (base_len:4 BE || exp_len:4 BE || mod_len:4 BE || base || exp ||
 * modulus) from read_input, calls `zkvm_modexp`, writes mod_len bytes
 * (BE) via write_output.
 */

#include <stddef.h>
#include <stdint.h>

#include <zkvm_accelerators.h>

extern void read_input(const uint8_t **buf_ptr, size_t *buf_size);
extern void write_output(const uint8_t *output, size_t size);

static uint32_t read_u32_be(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

int main(void) {
  const uint8_t *buf = 0;
  size_t size = 0;
  read_input(&buf, &size);
  if (size < 12) return 1;

  uint32_t base_len = read_u32_be(buf);
  uint32_t exp_len = read_u32_be(buf + 4);
  uint32_t mod_len = read_u32_be(buf + 8);
  if ((size_t)12 + base_len + exp_len + mod_len != size) return 1;
  /* Bound the mod_len so we can allocate on the stack. */
  if (mod_len > 256) return 1;

  const uint8_t *base = buf + 12;
  const uint8_t *exp = base + base_len;
  const uint8_t *modulus = exp + exp_len;

  uint8_t out[256];
  zkvm_status status =
      zkvm_modexp(base, base_len, exp, exp_len, modulus, mod_len, out);
  if (status != ZKVM_EOK) return 1;

  write_output(out, mod_len);
  return 0;
}
