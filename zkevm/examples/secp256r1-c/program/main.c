/*
 * secp256r1-c — P-256 ECDSA verify precompile demo, C edition.
 *
 * Reads a 160-byte input (32-byte message hash || 64-byte signature ||
 * 64-byte uncompressed pubkey x||y) from read_input, calls
 * `zkvm_secp256r1_verify` (Ethereum precompile 0x100 / EIP-7212), and
 * writes a single byte (0 or 1) via write_output.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zkvm_accelerators.h>

extern void read_input(const uint8_t **buf_ptr, size_t *buf_size);
extern void write_output(const uint8_t *output, size_t size);

int main(void) {
  const uint8_t *buf = 0;
  size_t size = 0;
  read_input(&buf, &size);

  if (size != 32 + 64 + 64) {
    return 1;
  }

  zkvm_secp256r1_hash msg;
  zkvm_secp256r1_signature sig;
  zkvm_secp256r1_pubkey pubkey;
  for (size_t i = 0; i < sizeof msg.data; ++i) msg.data[i] = buf[i];
  for (size_t i = 0; i < sizeof sig.data; ++i) sig.data[i] = buf[32 + i];
  for (size_t i = 0; i < sizeof pubkey.data; ++i) pubkey.data[i] = buf[32 + 64 + i];

  bool verified = false;
  zkvm_status status = zkvm_secp256r1_verify(&msg, &sig, &pubkey, &verified);
  if (status != ZKVM_EOK) {
    return 1;
  }

  uint8_t out = verified ? 1u : 0u;
  write_output(&out, 1);
  return 0;
}
