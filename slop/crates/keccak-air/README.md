# slop-keccak-air

Native Keccak-f trace generation for SP1's SLOP machine.

The trace representation is based on the certified optimized AIR from
[`keccak.fast`](https://github.com/Layr-Labs/keccak.fast). SP1's machine AIR
adds explicit theta parities and input/output limbs to satisfy two production
backend requirements:

- AIR constraints have degree at most three.
- Interaction values are affine expressions.

The resulting Keccak core has 2,471 columns. SP1 adds seven VM context columns,
for a 2,478-column chip instead of the previous 2,640-column chip.

The SP1 controller interaction remains unchanged: each row receives
`(clock, state address, round index, 100 state limbs)` and sends the same
message shape with the next round index and output state.

The exact SP1 AIR is an adaptation of the certified standalone AIR, not the
same polynomial artifact. It must therefore be tested and reviewed as its own
production constraint system.

---

Part of [SLOP](https://github.com/succinctlabs/sp1/tree/dev/slop), the Succinct Library of Polynomials.
