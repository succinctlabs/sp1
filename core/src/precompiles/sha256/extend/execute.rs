use crate::{
    precompiles::sha256::ShaExtendEvent,
    runtime::{AccessPosition, Register, Runtime},
};

use super::ShaExtendChip;

impl ShaExtendChip {
    pub fn execute(rt: &mut Runtime) -> (u32, u32, u32) {
        // The number of cycles it takes to perform this precompile.
        const NB_SHA_EXTEND_CYCLES: u32 = 48 * 20;

        // Initialize the registers.
        let t0 = Register::X5;
        let a0 = Register::X10;

        // Temporarily set the clock to the number of cycles it takes to perform this precompile as
        // reading `w_ptr` happens on this clock.
        rt.clk += NB_SHA_EXTEND_CYCLES;

        // Read `w_ptr` from register a0 or x5.
        let w_ptr = rt.register(a0);
        let w: [u32; 64] = (0..64)
            .map(|i| rt.word(w_ptr + i * 4))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // Set the CPU table values with some dummy values.
        let (a, b, c) = (w_ptr, rt.rr(t0, AccessPosition::B), 0);
        rt.rw(a0, a);

        // We'll save the current record and restore it later so that the CPU event gets emitted
        // correctly.
        let t = rt.record;

        // Set the clock back to the original value and begin executing the precompile.
        rt.clk -= NB_SHA_EXTEND_CYCLES;
        let clk_init = rt.clk;
        let w_ptr_init = w_ptr;
        let w_init = w.clone();
        let mut w_i_minus_15_reads = Vec::new();
        let mut w_i_minus_2_reads = Vec::new();
        let mut w_i_minus_16_reads = Vec::new();
        let mut w_i_minus_7_reads = Vec::new();
        let mut w_i_writes = Vec::new();
        for i in 16..64 {
            // Read w[i-15].
            let w_i_minus_15 = rt.mr(w_ptr + (i - 15) * 4, AccessPosition::Memory);
            w_i_minus_15_reads.push(rt.record.memory);
            rt.clk += 4;

            // Compute `s0`.
            let s0 =
                w_i_minus_15.rotate_right(7) ^ w_i_minus_15.rotate_right(18) ^ (w_i_minus_15 >> 3);

            // Read w[i-2].
            let w_i_minus_2 = rt.mr(w_ptr + (i - 2) * 4, AccessPosition::Memory);
            w_i_minus_2_reads.push(rt.record.memory);
            rt.clk += 4;

            // Compute `s1`.
            let s1 =
                w_i_minus_2.rotate_right(17) ^ w_i_minus_2.rotate_right(19) ^ (w_i_minus_2 >> 10);

            // Read w[i-16].
            let w_i_minus_16 = rt.mr(w_ptr + (i - 16) * 4, AccessPosition::Memory);
            w_i_minus_16_reads.push(rt.record.memory);
            rt.clk += 4;

            // Read w[i-7].
            let w_i_minus_7 = rt.mr(w_ptr + (i - 7) * 4, AccessPosition::Memory);
            w_i_minus_7_reads.push(rt.record.memory);
            rt.clk += 4;

            // Compute `w_i`.
            let w_i = s1
                .wrapping_add(w_i_minus_16)
                .wrapping_add(s0)
                .wrapping_add(w_i_minus_7);

            // Write w[i].
            rt.mr(w_ptr + i * 4, AccessPosition::Memory);
            rt.mw(w_ptr + i * 4, w_i, AccessPosition::Memory);
            w_i_writes.push(rt.record.memory);
            rt.clk += 4;
        }

        // Push the SHA extend event.
        rt.segment.sha_extend_events.push(ShaExtendEvent {
            clk: clk_init,
            w_ptr: w_ptr_init,
            w: w_init,
            w_i_minus_15_reads: w_i_minus_15_reads.try_into().unwrap(),
            w_i_minus_2_reads: w_i_minus_2_reads.try_into().unwrap(),
            w_i_minus_16_reads: w_i_minus_16_reads.try_into().unwrap(),
            w_i_minus_7_reads: w_i_minus_7_reads.try_into().unwrap(),
            w_i_writes: w_i_writes.try_into().unwrap(),
        });

        // Restore the original record.
        rt.record = t;

        (a, b, c)
    }
}
