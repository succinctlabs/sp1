use itertools::Itertools;
use sp1_jit::{Interrupt, RiscRegister, SyscallContext};

#[allow(clippy::unnecessary_wraps)]
pub fn sig_return_syscall(
    ctx: &mut impl SyscallContext,
    addr: u64,
    _: u64,
) -> Result<Option<u64>, Interrupt> {
    let regs: Vec<_> = ctx.mr_slice_without_prot(addr + 8, 31).into_iter().copied().collect();

    ctx.bump_memory_clk();
    for (reg, value) in RiscRegister::all_registers().iter().skip(1).zip_eq(regs.iter()) {
        ctx.rw(*reg, *value);
    }

    // SP1 forces updating of X5 with ecall result
    Ok(Some(regs[4]))
}
