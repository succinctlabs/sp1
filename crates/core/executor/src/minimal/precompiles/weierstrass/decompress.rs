use sp1_curves::EllipticCurve;
use sp1_jit::{Interrupt, SyscallContext};

/// Execute a weierstrass decompress syscall.
///
/// The Weierstrass decompress precompiles are decommissioned: they have no AIR, so there is no
/// chip to emit an event against and nothing this could return that would be provable. This is
/// reached only when a guest program calls one of the deprecated
/// `syscall_{secp256k1,secp256r1,bls12381}_decompress` wrappers.
pub(crate) fn weierstrass_decompress_syscall<E: EllipticCurve>(
    _ctx: &mut impl SyscallContext,
    _slice_ptr: u64,
    _sign_bit: u64,
) -> Result<Option<u64>, Interrupt> {
    panic!(
        "the guest program called the {} decompress precompile, which is decommissioned: it has \
         no executor implementation and no AIR, so it can be neither executed nor proven. Remove \
         the decompress syscall from the guest program and decompress in Rust instead. See \
         https://github.com/succinctlabs/sp1/issues/2926",
        E::CURVE_TYPE
    );
}
