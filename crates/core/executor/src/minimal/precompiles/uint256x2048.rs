use sp1_jit::{Interrupt, SyscallContext};

pub(crate) unsafe fn u256x2048_mul(
    _ctx: &mut impl SyscallContext,
    _arg1: u64,
    _arg2: u64,
) -> Result<Option<u64>, Interrupt> {
    panic!("This method should be deprecated.");
}
