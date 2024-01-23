use crate::{
    precompiles::sha256::{ShaCompressEvent, SHA_COMPRESS_K},
    runtime::{AccessPosition, Register, Runtime},
};

use super::ShaCompressChip;

impl ShaCompressChip {
    pub fn execute(rt: &mut Runtime) -> u32 {
        let t0 = Register::X5;
        let a0 = Register::X10;

        // The number of cycles it takes to perform this precompile.
        const NB_SHA_COMPRESS_CYCLES: u32 = 8 * 4 + 64 * 4 + 8 * 4;

        // Temporarily set the clock to the number of cycles it takes to perform
        // this precompile as reading `w_ptr` happens on this clock.
        rt.clk += NB_SHA_COMPRESS_CYCLES;

        // Read `w_ptr` from register a0 or x5.
        let w_ptr = rt.register(a0);
        let mut w = Vec::new();
        for i in 0..64 {
            w.push(rt.word(w_ptr + i * 4));
        }

        // Set the CPU table values with some dummy values.
        let (fa, fb, fc) = (w_ptr, rt.rr(t0, AccessPosition::B), 0);
        rt.rw(a0, fa);

        // We'll save the current record and restore it later so that the CPU
        // event gets emitted correctly.
        let t = rt.record;

        // Set the clock back to the original value and begin executing the
        // precompile.
        rt.clk -= NB_SHA_COMPRESS_CYCLES;
        let saved_clk = rt.clk;
        let saved_w_ptr = w_ptr;
        let saved_w = w.clone();
        let mut h_read_records = Vec::new();
        let mut w_i_read_records = Vec::new();
        let mut h_write_records = Vec::new();

        // Execute the "initialize" phase.
        const H_START_IDX: u32 = 64;
        let mut hx = [0u32; 8];
        for i in 0..8 {
            hx[i] = rt.mr(w_ptr + (H_START_IDX + i as u32) * 4, AccessPosition::Memory);
            h_read_records.push(rt.record.memory);
            rt.clk += 4;
        }

        // Execute the "compress" phase.
        let mut a = hx[0];
        let mut b = hx[1];
        let mut c = hx[2];
        let mut d = hx[3];
        let mut e = hx[4];
        let mut f = hx[5];
        let mut g = hx[6];
        let mut h = hx[7];
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let w_i = rt.mr(w_ptr + i * 4, AccessPosition::Memory);
            w_i_read_records.push(rt.record.memory);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA_COMPRESS_K[i as usize])
                .wrapping_add(w_i);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);

            rt.clk += 4;
        }

        // Execute the "finalize" phase.
        let v = [a, b, c, d, e, f, g, h];
        for i in 0..8 {
            rt.mr(w_ptr + (H_START_IDX + i as u32) * 4, AccessPosition::Memory);
            rt.mw(
                w_ptr.wrapping_add((H_START_IDX + i as u32) * 4),
                hx[i].wrapping_add(v[i]),
                AccessPosition::Memory,
            );
            h_write_records.push(rt.record.memory);
            rt.clk += 4;
        }

        // Push the SHA extend event.
        rt.segment.sha_compress_events.push(ShaCompressEvent {
            clk: saved_clk,
            w_and_h_ptr: saved_w_ptr,
            w: saved_w.try_into().unwrap(),
            h: hx,
            h_read_records: h_read_records.try_into().unwrap(),
            w_i_read_records: w_i_read_records.try_into().unwrap(),
            h_write_records: h_write_records.try_into().unwrap(),
        });

        // Restore the original record.
        rt.record = t;

        fc
    }
}
