use crate::{
    runtime::{Register, Syscall},
    syscall::precompiles::{
        sha256::{ShaCompressEvent, SHA_COMPRESS_K},
        SyscallContext,
    },
};

use super::ShaCompressChip;

impl Syscall for ShaCompressChip {
    fn num_extra_cycles(&self) -> u32 {
        8
    }

    fn execute(&self, rt: &mut SyscallContext) -> u32 {
        // Read `w_ptr` from register a0.
        let w_ptr = rt.register_unsafe(Register::X10);

        let saved_clk = rt.clk;
        let mut w_i_read_records = Vec::new();

        // Execute the "initialize" phase.
        let h_start_index = 64u32;
        let h_address = w_ptr.wrapping_add(4 * h_start_index);
        let (h_read_records, hx) = rt.mr_slice(h_address, 8);
        rt.clk += 4;

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
        }

        // Execute the "finalize" phase.
        let h_write_records = {
            let values = [a, b, c, d, e, f, g, h]
                .iter()
                .zip(hx.iter())
                .map(|(x, y)| *x + *y)
                .collect::<Vec<u32>>();
            rt.mw_slice(h_address, &values)
        };
        rt.clk += 4;

        // Push the SHA extend event.
        let shard = rt.current_shard();
        rt.record_mut().sha_compress_events.push(ShaCompressEvent {
            shard,
            clk: saved_clk,
            w_and_h_ptr: w_ptr,
            w: original_w,
            h: hx.try_into().unwrap(),
            h_read_records: h_read_records.try_into().unwrap(),
            w_i_read_records,
            h_write_records: h_write_records.try_into().unwrap(),
        });

        w_ptr
    }
}
