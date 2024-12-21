use std::marker::PhantomData;

use sp1_curves::{CurveType, EllipticCurve};

use crate::{
    events::{create_ec_decompress_event, PrecompileEvent},
    syscalls::{Syscall, SyscallCode, SyscallContext},
};

pub(crate) struct WeierstrassDecompressSyscall<E: EllipticCurve> {
    _phantom: std::marker::PhantomData<E>,
}

impl<E: EllipticCurve> WeierstrassDecompressSyscall<E> {
    /// Create a new instance of the [`WeierstrassDecompressSyscall`].
    pub const fn new() -> Self {
        Self { _phantom: PhantomData }
    }
}

impl<E: EllipticCurve> Syscall for WeierstrassDecompressSyscall<E> {
    fn execute(
        &self,
        rt: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        let event = create_ec_decompress_event::<E>(rt, arg1, arg2);
        let syscall_event =
            rt.rt.syscall_event(event.clk, None, None, syscall_code, arg1, arg2, rt.next_pc);
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => rt.add_precompile_event(
                syscall_code,
                syscall_event,
                PrecompileEvent::Secp256k1Decompress(event),
            ),
            CurveType::Secp256r1 => rt.record_mut().add_precompile_event(
                syscall_code,
                syscall_event,
                PrecompileEvent::Secp256r1Decompress(event),
            ),
            CurveType::Bls12381 => rt.record_mut().add_precompile_event(
                syscall_code,
                syscall_event,
                PrecompileEvent::Bls12381Decompress(event),
            ),
            _ => panic!("Unsupported curve"),
        }
        None
    }

    fn num_extra_cycles(&self) -> u32 {
        0
    }
}
