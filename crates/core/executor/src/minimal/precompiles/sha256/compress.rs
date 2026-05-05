use sp1_jit::{Interrupt, SyscallContext};

pub const SHA_COMPRESS_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// The SHA-256 compression function.
///
/// This function is called by the JIT compiler when the SHA-256 compression function is
/// needed.
///
/// # Safety
/// - The memory in `ctx` is valid for the duration of the function call.
#[allow(clippy::pedantic)]
pub(crate) unsafe fn sha256_compress(
    ctx: &mut impl SyscallContext,
    arg1: u64,
    arg2: u64,
) -> Result<Option<u64>, Interrupt> {
    let w_ptr = arg1;
    let h_ptr = arg2;

    let clk = ctx.get_current_clk();
    ctx.read_slice_check(h_ptr, 8)?;
    ctx.bump_memory_clk();
    ctx.read_slice_check(w_ptr, 64)?;
    ctx.bump_memory_clk();
    ctx.write_slice_check(h_ptr, 8)?;

    ctx.set_clk(clk);
    // Execute the "initialize" phase where we read in the h values.
    let hx: Vec<_> = ctx.mr_slice_without_prot(h_ptr, 8).into_iter().map(|h| *h as u32).collect();

    ctx.bump_memory_clk();

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
        let w_i = ctx.mr_without_prot(w_ptr + i as u64 * 8) as u32;
        original_w.push(w_i);
        let temp1 =
            h.wrapping_add(s1).wrapping_add(ch).wrapping_add(SHA_COMPRESS_K[i]).wrapping_add(w_i);
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
    ctx.bump_memory_clk();

    // Execute the "finalize" phase.
    let v = [
        a.wrapping_add(hx[0]) as u64,
        b.wrapping_add(hx[1]) as u64,
        c.wrapping_add(hx[2]) as u64,
        d.wrapping_add(hx[3]) as u64,
        e.wrapping_add(hx[4]) as u64,
        f.wrapping_add(hx[5]) as u64,
        g.wrapping_add(hx[6]) as u64,
        h.wrapping_add(hx[7]) as u64,
    ];
    ctx.mw_slice_without_prot(h_ptr, &v);

    Ok(None)
}
