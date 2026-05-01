use sp1_jit::{Interrupt, SyscallContext};
use sp1_primitives::consts::{PAGE_SIZE, PERMITTED_PROTS};

use crate::memory::MAX_LOG_ADDR;

#[allow(clippy::unnecessary_wraps)]
pub fn mprotect_syscall(
    ctx: &mut impl SyscallContext,
    addr: u64,
    prot: u64,
) -> Result<Option<u64>, Interrupt> {
    let prot: u8 = prot.try_into().expect("prot must be 8 bits");

    assert!(addr.is_multiple_of(PAGE_SIZE as u64), "addr must be page aligned");
    assert!(addr < 1 << MAX_LOG_ADDR, "addr must be less than 2^48");
    assert!(PERMITTED_PROTS.contains(&prot), "prot must be a permitted combination");
    assert!(!ctx.is_unconstrained(), "mprotect is disabled in unconstrained mode");

    ctx.page_prot_write(addr, prot);

    Ok(None)
}

#[allow(clippy::unnecessary_wraps)]
pub fn mprotect_flush_syscall(
    ctx: &mut impl SyscallContext,
    _: u64,
    _: u64,
) -> Result<Option<u64>, Interrupt> {
    ctx.page_prot_flush();

    Ok(None)
}
