use num::BigUint;
use sp1_curves::{params::NumWords, weierstrass::FpOpField};
use sp1_jit::{Interrupt, SyscallContext};
use sp1_primitives::consts::u64_to_u32;
use typenum::Unsigned;

use crate::events::FieldOperation;

pub(crate) unsafe fn fp_op_syscall<P: FpOpField>(
    ctx: &mut impl SyscallContext,
    arg1: u64,
    arg2: u64,
    op: FieldOperation,
) -> Result<Option<u64>, Interrupt> {
    let x_ptr = arg1;
    if !x_ptr.is_multiple_of(8) {
        panic!();
    }
    let y_ptr = arg2;
    if !y_ptr.is_multiple_of(8) {
        panic!();
    }

    let num_words = <P as NumWords>::WordsFieldElement::USIZE;

    let clk = ctx.get_current_clk();
    ctx.read_slice_check(y_ptr, num_words)?;
    ctx.bump_memory_clk();
    ctx.read_write_slice_check(x_ptr, num_words)?;

    ctx.set_clk(clk);

    let x_32 = u64_to_u32(ctx.mr_slice_unsafe(x_ptr, num_words));
    let y_32 = u64_to_u32(ctx.mr_slice_without_prot(y_ptr, num_words));

    let modulus = &BigUint::from_bytes_le(P::MODULUS);
    let a = BigUint::from_slice(&x_32) % modulus;
    let b = BigUint::from_slice(&y_32) % modulus;

    let result = match op {
        FieldOperation::Add => (a + b) % modulus,
        FieldOperation::Sub => ((a + modulus) - b) % modulus,
        FieldOperation::Mul => (a * b) % modulus,
        _ => panic!("Unsupported operation"),
    };
    let mut result = result.to_u64_digits();
    result.resize(num_words, 0);

    // Bump the clock before writing to memory.
    ctx.bump_memory_clk();
    ctx.mw_slice_without_prot(x_ptr, &result);

    Ok(None)
}
