use crate::{
    precompiles::{
        sha256::{ShaCompressEvent, SHA_COMPRESS_K},
        PrecompileRuntime,
    },
    runtime::Register,
};

use super::ShaCompressChip;

impl ShaCompressChip {
    pub const NUM_CYCLES: u32 = 8 * 4 + 64 * 4 + 8 * 4;
    pub fn execute(rt: &mut PrecompileRuntime) -> u32 {
        // Read `w_ptr` from register a0.
        let w_ptr = rt.register_unsafe(Register::X10);

        // Set the clock back to the original value and begin executing the
        // precompile.
        let saved_clk = rt.clk;
        let saved_w_ptr = w_ptr;
        let mut h_read_records = Vec::new();
        let mut w_i_read_records = Vec::new();
        let mut h_write_records = Vec::new();

        // Execute the "initialize" phase.
        const H_START_IDX: u32 = 64;
        let mut hx = [0u32; 8];
        for i in 0..8 {
            let (record, value) = rt.mr(w_ptr + (H_START_IDX + i as u32) * 4);
            h_read_records.push(record);
            hx[i] = value;
            rt.clk += 4;
        }

        let mut original_w = Vec::new();
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
            let (record, w_i) = rt.mr(w_ptr + i * 4);
            original_w.push(w_i);
            w_i_read_records.push(record);
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
            let record = rt.mw(
                w_ptr.wrapping_add((H_START_IDX + i as u32) * 4),
                hx[i].wrapping_add(v[i]),
            );
            h_write_records.push(record);
            rt.clk += 4;
        }

        // Push the SHA extend event.
        rt.segment_mut().sha_compress_events.push(ShaCompressEvent {
            clk: saved_clk,
            w_and_h_ptr: saved_w_ptr,
            w: original_w.try_into().unwrap(),
            h: hx,
            h_read_records: h_read_records.try_into().unwrap(),
            w_i_read_records: w_i_read_records.try_into().unwrap(),
            h_write_records: h_write_records.try_into().unwrap(),
        });

        w_ptr
    }
}
