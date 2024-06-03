use super::ShaCompressChip;
use crate::{
    runtime::Syscall,
    syscall::precompiles::{
        sha256::{ShaCompressEvent, SHA_COMPRESS_K},
        SyscallContext,
    },
};

impl Syscall for ShaCompressChip {
    fn num_extra_cycles(&self) -> u32 {
        1
    }

    fn execute(&self, rt: &mut SyscallContext, arg1: u32, arg2: u32) -> Option<u32> {
        let w_ptr = arg1;
        let h_ptr = arg2;
        assert_ne!(w_ptr, h_ptr);

        let start_clk = rt.clk;
        let mut h_read_records = Vec::new();
        let mut w_i_read_records = Vec::new();
        let mut h_write_records = Vec::new();

        // Execute the "initialize" phase where we read in the h values.
        let mut hx = [0u32; 8];
        for i in 0..8 {
            let (record, value) = rt.mr(h_ptr + i as u32 * 4);
            h_read_records.push(record);
            hx[i] = value;
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
        }
        // Increment the clk by 1 before writing to h, since we've already read h at the start_clk
        // during the initialization phase.
        rt.clk += 1;

        // Execute the "finalize" phase.
        let v = [a, b, c, d, e, f, g, h];
        for i in 0..8 {
            let record = rt.mw(h_ptr + i as u32 * 4, hx[i].wrapping_add(v[i]));
            h_write_records.push(record);
        }

        // Push the SHA extend event.
        let lookup_id = rt.syscall_lookup_id;
        let shard = rt.current_shard();
        let channel = rt.current_channel();
        rt.record_mut().sha_compress_events.push(ShaCompressEvent {
            lookup_id,
            shard,
            channel,
            clk: start_clk,
            w_ptr,
            h_ptr,
            w: original_w,
            h: hx,
            h_read_records: h_read_records.try_into().unwrap(),
            w_i_read_records,
            h_write_records: h_write_records.try_into().unwrap(),
        });

        None
    }
}
