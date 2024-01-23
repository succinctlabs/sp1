use crate::runtime::{AccessPosition, Register, Runtime};

use super::KeccakPermuteChip;

const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

impl KeccakPermuteChip {
    pub fn execute(rt: &mut Runtime) -> (u32, u32, u32) {
        let t0 = Register::X5;
        let a0 = Register::X10;

        // The number of cycles it takes to perform this precompile.
        const NB_KECCAK_PERMUTE_CYCLES: u32 = 24 * 4;
        const NUM_ROUNDS: usize = 24;

        // Temporarily set the clock to the number of cycles it takes to perform
        // this precompile as reading `(pre|post)image_ptr` happens on this clock.
        rt.clk += NB_KECCAK_PERMUTE_CYCLES;
        let preimage_ptr = rt.register(a0);

        // Set the CPU table values with some dummy values.
        let (fa, fb, fc) = (preimage_ptr, rt.rr(t0, AccessPosition::B), 0);
        rt.rw(a0, fa);

        // We'll save the current record and restore it later so that the CPU
        // event gets emitted correctly.
        let t = rt.record;

        // Set the clock back to the original value and begin executing the
        // precompile.
        rt.clk -= NB_KECCAK_PERMUTE_CYCLES;

        let saved_clk = rt.clk;
        let saved_preimage_ptr = preimage_ptr;
        let mut preimage_read_records = Vec::new();
        let mut postimage_write_records = Vec::new();

        // Read `preimage_ptr` from register a0 or x5.
        let mut preimage = Vec::new();
        for i in (0..(25 * 2)).step_by(2) {
            let most_sig = rt.mr(preimage_ptr + i * 4, AccessPosition::Memory);
            preimage_read_records.push(rt.record.memory);
            let least_sig = rt.mr(preimage_ptr + (i + 1) * 4, AccessPosition::Memory);
            preimage_read_records.push(rt.record.memory);
            preimage.push(least_sig as u64 + ((most_sig as u64) << 32));
        }

        let saved_preimage = preimage.clone();

        for i in 0..NUM_ROUNDS {
            let mut array: [u64; 5 * 5] = [0; 5 * 5];

            // Theta
            for x in 0..5 {
                for y_count in 0..5 {
                    let y = y_count * 5;
                    array[x] ^= preimage[x + y];
                }
            }

            for x in 0..5 {
                for y_count in 0..5 {
                    let y = y_count * 5;
                    preimage[y + x] ^= array[(x + 4) % 5] ^ array[(x + 1) % 5].rotate_left(1);
                }
            }

            // Rho and pi
            let mut last = preimage[1];
            for x in 0..24 {
                array[0] = preimage[PI[x]];
                preimage[PI[x]] = last.rotate_left(RHO[x]);
                last = array[0];
            }

            // Chi
            for y_step in 0..5 {
                let y = y_step * 5;

                for x in 0..5 {
                    array[x] = preimage[y + x];
                }

                for x in 0..5 {
                    preimage[y + x] = array[x] ^ ((!array[(x + 1) % 5]) & (array[(x + 2) % 5]));
                }
            }

            // Iota
            preimage[0] ^= RC[i];
        }

        rt.clk += NB_KECCAK_PERMUTE_CYCLES;
        for i in 0..25 {
            let most_sig = ((preimage[i] >> 32) & 0xFFFFFFFF) as u32;
            let least_sig = (preimage[i] & 0xFFFFFFFF) as u32;
            rt.mw(
                preimage_ptr + (2 * i as u32) * 4,
                most_sig,
                AccessPosition::Memory,
            );
            postimage_write_records.push(rt.record.memory);
            rt.mw(
                preimage_ptr + (2 * i as u32 + 1) * 4,
                least_sig,
                AccessPosition::Memory,
            );
            postimage_write_records.push(rt.record.memory);
        }

        // // Push the SHA extend event.
        // rt.segment.sha_compress_events.push(ShaCompressEvent {
        //     clk: saved_clk,
        //     w_and_h_ptr: saved_w_ptr,
        //     w: saved_w.try_into().unwrap(),
        //     h: hx,
        //     h_read_records: h_read_records.try_into().unwrap(),
        //     w_i_read_records: w_i_read_records.try_into().unwrap(),
        //     h_write_records: h_write_records.try_into().unwrap(),
        // });

        // Restore the original record.
        rt.record = t;

        (fa, fb, fc)
    }
}
