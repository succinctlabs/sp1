/*
 * ecrecover-c — Ethereum precompile 0x01 demo, C edition.
 *
 * Reads (msg_hash:32 || sig:64 || recid:1) from read_input, calls
 * `zkvm_secp256k1_ecrecover`, writes the 64-byte uncompressed pubkey
 * (x || y) via write_output.
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
  if (size != 32 + 64 + 1) return 1;

  zkvm_secp256k1_hash msg;
  zkvm_secp256k1_signature sig;
  for (size_t i = 0; i < sizeof msg.data; ++i) msg.data[i] = buf[i];
  for (size_t i = 0; i < sizeof sig.data; ++i) sig.data[i] = buf[32 + i];
  uint8_t recid = buf[32 + 64];

  zkvm_secp256k1_pubkey out = {0};
  zkvm_status status = zkvm_secp256k1_ecrecover(&msg, &sig, recid, &out);
  if (status != ZKVM_EOK) return 1;

  write_output(out.data, sizeof out.data);
  return 0;
}
