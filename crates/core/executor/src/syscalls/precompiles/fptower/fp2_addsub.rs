use num::BigUint;
use sp1_curves::{
    params::NumWords,
    weierstrass::{FieldType, FpOpField},
};
use std::marker::PhantomData;
use typenum::Unsigned;

use crate::{
    events::{FieldOperation, Fp2AddSubEvent, PrecompileEvent},
    syscalls::{Syscall, SyscallCode, SyscallContext},
};

pub struct Fp2AddSubSyscall<P> {
    op: FieldOperation,
    _marker: PhantomData<P>,
}

impl<P> Fp2AddSubSyscall<P> {
    pub const fn new(op: FieldOperation) -> Self {
        Self { op, _marker: PhantomData }
    }
}

impl<P: FpOpField> Syscall for Fp2AddSubSyscall<P> {
    fn execute(
        &self,
        rt: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        let clk = rt.clk;
        let x_ptr = arg1;
        if x_ptr % 4 != 0 {
            panic!();
        }
        let y_ptr = arg2;
        if y_ptr % 4 != 0 {
            panic!();
        }

        let num_words = <P as NumWords>::WordsCurvePoint::USIZE;

        let x = rt.slice_unsafe(x_ptr, num_words);
        let (y_memory_records, y) = rt.mr_slice(y_ptr, num_words);
        rt.clk += 1;

        let (ac0, ac1) = x.split_at(x.len() / 2);
        let (bc0, bc1) = y.split_at(y.len() / 2);

        let ac0 = &BigUint::from_slice(ac0);
        let ac1 = &BigUint::from_slice(ac1);
        let bc0 = &BigUint::from_slice(bc0);
        let bc1 = &BigUint::from_slice(bc1);
        let modulus = &BigUint::from_bytes_le(P::MODULUS);

        let (c0, c1) = match self.op {
            FieldOperation::Add => ((ac0 + bc0) % modulus, (ac1 + bc1) % modulus),
            FieldOperation::Sub => {
                ((ac0 + modulus - bc0) % modulus, (ac1 + modulus - bc1) % modulus)
            }
            _ => panic!("Invalid operation"),
        };

        let mut result =
            c0.to_u32_digits().into_iter().chain(c1.to_u32_digits()).collect::<Vec<u32>>();

        result.resize(num_words, 0);
        let x_memory_records = rt.mw_slice(x_ptr, &result);

        let lookup_id = rt.syscall_lookup_id;
        let shard = rt.current_shard();
        let op = self.op;
        let event = Fp2AddSubEvent {
            lookup_id,
            shard,
            clk,
            op,
            x_ptr,
            x,
            y_ptr,
            y,
            x_memory_records,
            y_memory_records,
            local_mem_access: rt.postprocess(),
        };
        match P::FIELD_TYPE {
            // All the fp2 add and sub events for a given curve are coalesced to the curve's fp2 add operation.  Only check for
            // that operation.
            // TODO:  Fix this.
            FieldType::Bn254 => {
                let syscall_code_key = match syscall_code {
                    SyscallCode::BN254_FP2_ADD | SyscallCode::BN254_FP2_SUB => {
                        SyscallCode::BN254_FP2_ADD
                    }
                    _ => unreachable!(),
                };

                let syscall_event = rt.rt.syscall_event(
                    clk,
                    syscall_code.syscall_id(),
                    arg1,
                    arg2,
                    event.lookup_id,
                );
                rt.record_mut().add_precompile_event(
                    syscall_code_key,
                    syscall_event,
                    PrecompileEvent::Bn254Fp2AddSub(event),
                );
            }
            FieldType::Bls12381 => {
                let syscall_code_key = match syscall_code {
                    SyscallCode::BLS12381_FP2_ADD | SyscallCode::BLS12381_FP2_SUB => {
                        SyscallCode::BLS12381_FP2_ADD
                    }
                    _ => unreachable!(),
                };

                let syscall_event = rt.rt.syscall_event(
                    clk,
                    syscall_code.syscall_id(),
                    arg1,
                    arg2,
                    event.lookup_id,
                );
                rt.record_mut().add_precompile_event(
                    syscall_code_key,
                    syscall_event,
                    PrecompileEvent::Bls12381Fp2AddSub(event),
                );
            }
        }
        None
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}
