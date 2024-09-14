use std::marker::PhantomData;

use sp1_curves::{CurveType, EllipticCurve};

use crate::{
    events::{create_ec_add_event, PrecompileEvent},
    syscalls::{Syscall, SyscallCode, SyscallContext},
};

pub(crate) struct WeierstrassAddAssignSyscall<E: EllipticCurve> {
    _phantom: PhantomData<E>,
}

impl<E: EllipticCurve> WeierstrassAddAssignSyscall<E> {
    /// Create a new instance of the [`WeierstrassAddAssignSyscall`].
    pub const fn new() -> Self {
        Self { _phantom: PhantomData }
    }
}

impl<E: EllipticCurve> Syscall for WeierstrassAddAssignSyscall<E> {
    fn execute(
        &self,
        rt: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        let event = create_ec_add_event::<E>(rt, arg1, arg2);
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => rt
                .record_mut()
                .add_precompile_event(syscall_code, PrecompileEvent::Secp256k1Add(event)),
            CurveType::Bn254 => {
                rt.record_mut()
                    .add_precompile_event(syscall_code, PrecompileEvent::Bn254Add(event));
            }
            CurveType::Bls12381 => rt
                .record_mut()
                .add_precompile_event(syscall_code, PrecompileEvent::Bls12381Add(event)),
            _ => panic!("Unsupported curve"),
        }
        None
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}
