use sp1_curves::EllipticCurve;
use sp1_jit::{Interrupt, SyscallContext};

/// Execute a weierstrass add assign syscall.
pub(crate) unsafe fn weierstrass_add_assign_syscall<E: EllipticCurve>(
    ctx: &mut impl SyscallContext,
    arg1: u64,
    arg2: u64,
) -> Result<Option<u64>, Interrupt> {
    crate::minimal::precompiles::ec::ec_add::<E>(ctx, arg1, arg2).map(|()| None)
}
