use std::marker::PhantomData;

use sp1_curves::{CurveType, EllipticCurve};

use crate::{
    events::{create_ec_double_event, PrecompileEvent},
    syscalls::{Syscall, SyscallCode, SyscallContext},
};

pub(crate) struct WeierstrassDoubleAssignSyscall<E: EllipticCurve> {
    _phantom: std::marker::PhantomData<E>,
}

impl<E: EllipticCurve> WeierstrassDoubleAssignSyscall<E> {
    /// Create a new instance of the [`WeierstrassDoubleAssignSyscall`].
    pub const fn new() -> Self {
        Self { _phantom: PhantomData }
    }
}

impl<E: EllipticCurve> Syscall for WeierstrassDoubleAssignSyscall<E> {
    fn execute(
        &self,
        rt: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        let event = create_ec_double_event::<E>(rt, arg1, arg2);
        let syscall_event =
            rt.rt.syscall_event(event.clk, syscall_code.syscall_id(), arg1, arg2, event.lookup_id);
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => {
                rt.record_mut().add_precompile_event(
                    syscall_code,
                    syscall_event,
                    PrecompileEvent::Secp256k1Double(event),
                );
            }
            CurveType::Bn254 => {
                rt.record_mut().add_precompile_event(
                    syscall_code,
                    syscall_event,
                    PrecompileEvent::Bn254Double(event),
                );
            }
            CurveType::Bls12381 => {
                rt.record_mut().add_precompile_event(
                    syscall_code,
                    syscall_event,
                    PrecompileEvent::Bls12381Double(event),
                );
            }
            _ => panic!("Unsupported curve"),
        }
        None
    }

    fn num_extra_cycles(&self) -> u32 {
        0
    }
}
