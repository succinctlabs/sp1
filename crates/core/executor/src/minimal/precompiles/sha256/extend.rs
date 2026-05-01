use sp1_jit::{Interrupt, SyscallContext};
use sp1_primitives::consts::{PROT_READ, PROT_WRITE};

pub(crate) unsafe fn sha256_extend(
    ctx: &mut impl SyscallContext,
    arg1: u64,
    arg2: u64,
) -> Result<Option<u64>, Interrupt> {
    let w_ptr = arg1;
    assert!(arg2 == 0, "arg2 must be 0");

    ctx.prot_slice_check(w_ptr, 16, PROT_READ)?;
    ctx.bump_memory_clk();
    ctx.prot_slice_check(w_ptr + 16 * 8, 48, PROT_READ | PROT_WRITE)?;

    for i in 16..64 {
        // Read w[i-15].
        let w_i_minus_15 = ctx.mr_without_prot(w_ptr + (i - 15) as u64 * 8);

        // Compute `s0`.
        let s0 = (w_i_minus_15 as u32).rotate_right(7)
            ^ (w_i_minus_15 as u32).rotate_right(18)
            ^ ((w_i_minus_15 as u32) >> 3);

        // Read w[i-2].
        let w_i_minus_2 = ctx.mr_without_prot(w_ptr + (i - 2) as u64 * 8);

        // Compute `s1`.
        let s1 = (w_i_minus_2 as u32).rotate_right(17)
            ^ (w_i_minus_2 as u32).rotate_right(19)
            ^ ((w_i_minus_2 as u32) >> 10);

        // Read w[i-16].
        let w_i_minus_16 = ctx.mr_without_prot(w_ptr + (i - 16) as u64 * 8);

        // Read w[i-7].
        let w_i_minus_7 = ctx.mr_without_prot(w_ptr + (i - 7) as u64 * 8);

        // Compute `w_i`.
        let w_i =
            s1.wrapping_add(w_i_minus_16 as u32).wrapping_add(s0).wrapping_add(w_i_minus_7 as u32);

        // Write w[i].
        ctx.mw_without_prot(w_ptr + i as u64 * 8, w_i as u64);
        ctx.bump_memory_clk();
    }

    Ok(None)
}
