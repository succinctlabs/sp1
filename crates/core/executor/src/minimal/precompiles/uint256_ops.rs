use num::BigUint;

use crate::{events::Uint256Operation, SyscallCode};
use sp1_jit::{
    Interrupt,
    RiscRegister::{X12, X13, X14, X5},
    SyscallContext,
};
const U256_NUM_WORDS: usize = 4;

/// Executes uint256 operations: d, e <- ((a op b) + c) % (2^256), ((a op b) + c) // (2^256)
/// where op is either ADD or MUL.
///
/// Register layout:
/// - arg1 (a0): address of a (uint256)
/// - arg2 (a1): address of b (uint256)
/// - X12: address of c (uint256)
/// - X13: address of d (uint256, output low)
/// - X14: address of e (uint256, output high)
pub unsafe fn uint256_ops(
    ctx: &mut impl SyscallContext,
    arg1: u64,
    arg2: u64,
) -> Result<Option<u64>, Interrupt> {
    // Get the operation from the syscall code
    let syscall_id = ctx.rr(X5);
    let syscall_code = SyscallCode::from_u32(syscall_id as u32);
    let op = syscall_code.uint256_op_map();

    // Read addresses - arg1 and arg2 come from the syscall, others from registers
    let a_ptr = arg1;
    let b_ptr = arg2;
    let c_ptr = ctx.rr(X12);
    let d_ptr = ctx.rr(X13);
    let e_ptr = ctx.rr(X14);

    let clk = ctx.get_current_clk();
    ctx.read_slice_check(a_ptr, U256_NUM_WORDS)?;
    ctx.bump_memory_clk();
    ctx.read_slice_check(b_ptr, U256_NUM_WORDS)?;
    ctx.bump_memory_clk();
    ctx.read_slice_check(c_ptr, U256_NUM_WORDS)?;
    ctx.bump_memory_clk();
    ctx.write_slice_check(d_ptr, 4)?;
    ctx.bump_memory_clk();
    ctx.write_slice_check(e_ptr, 4)?;

    ctx.set_clk(clk);
    // Read input values (8 words = 32 bytes each for uint256) and convert to BigUint
    let uint256_a = {
        let a = ctx.mr_slice_without_prot(a_ptr, U256_NUM_WORDS);
        BigUint::from_slice(
            &a.into_iter().flat_map(|&x| [x as u32, (x >> 32) as u32]).collect::<Vec<_>>(),
        )
    };
    ctx.bump_memory_clk();

    let uint256_b = {
        let b = ctx.mr_slice_without_prot(b_ptr, U256_NUM_WORDS);
        BigUint::from_slice(
            &b.into_iter().flat_map(|&x| [x as u32, (x >> 32) as u32]).collect::<Vec<_>>(),
        )
    };
    ctx.bump_memory_clk();

    let uint256_c = {
        let c = ctx.mr_slice_without_prot(c_ptr, U256_NUM_WORDS);
        BigUint::from_slice(
            &c.into_iter().flat_map(|&x| [x as u32, (x >> 32) as u32]).collect::<Vec<_>>(),
        )
    };

    // Perform the operation: (a op b) + c
    let intermediate_result = match op {
        Uint256Operation::Add => uint256_a + uint256_b + uint256_c,
        Uint256Operation::Mul => uint256_a * uint256_b + uint256_c,
    };

    let mut u64_result = intermediate_result.to_u64_digits();
    u64_result.resize(8, 0);

    // Write results
    ctx.bump_memory_clk();
    ctx.mw_slice_without_prot(d_ptr, &u64_result[0..4]);

    ctx.bump_memory_clk();
    ctx.mw_slice_without_prot(e_ptr, &u64_result[4..8]);

    Ok(None)
}
