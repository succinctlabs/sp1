use sp1_curves::{edwards::EdwardsParameters, EllipticCurve};
use sp1_jit::{Interrupt, SyscallContext};

pub unsafe fn edwards_add<E: EdwardsParameters + EllipticCurve>(
    ctx: &mut impl SyscallContext,
    arg1: u64,
    arg2: u64,
) -> Result<Option<u64>, Interrupt> {
    crate::minimal::precompiles::ec::ec_add::<E>(ctx, arg1, arg2).map(|()| None)
}
