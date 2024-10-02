use num::BigUint;
use sp1_curves::{
    params::NumWords,
    weierstrass::{FieldType, FpOpField},
};
use std::marker::PhantomData;
use typenum::Unsigned;

use crate::{
    events::{FieldOperation, FpOpEvent, PrecompileEvent},
    syscalls::{Syscall, SyscallCode, SyscallContext},
};

pub struct FpOpSyscall<P> {
    op: FieldOperation,
    _marker: PhantomData<P>,
}

impl<P> FpOpSyscall<P> {
    pub const fn new(op: FieldOperation) -> Self {
        Self { op, _marker: PhantomData }
    }
}

impl<P: FpOpField> Syscall for FpOpSyscall<P> {
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

        let num_words = <P as NumWords>::WordsFieldElement::USIZE;

        let x = rt.slice_unsafe(x_ptr, num_words);
        let (y_memory_records, y) = rt.mr_slice(y_ptr, num_words);

        let modulus = &BigUint::from_bytes_le(P::MODULUS);
        let a = BigUint::from_slice(&x) % modulus;
        let b = BigUint::from_slice(&y) % modulus;

        let result = match self.op {
            FieldOperation::Add => (a + b) % modulus,
            FieldOperation::Sub => ((a + modulus) - b) % modulus,
            FieldOperation::Mul => (a * b) % modulus,
            _ => panic!("Unsupported operation"),
        };
        let mut result = result.to_u32_digits();
        result.resize(num_words, 0);

        rt.clk += 1;
        let x_memory_records = rt.mw_slice(x_ptr, &result);

        let lookup_id = rt.syscall_lookup_id;
        let shard = rt.current_shard();
        let event = FpOpEvent {
            lookup_id,
            shard,
            clk,
            x_ptr,
            x,
            y_ptr,
            y,
            op: self.op,
            x_memory_records,
            y_memory_records,
            local_mem_access: rt.postprocess(),
        };

        // Since all the Fp events are on the same table, we need to preserve the ordering of the
        // events b/c of the nonce.  In this table's trace_gen, the nonce is simply the row number.
        // Group all of the events for a specific curve into the same syscall code key.
        // TODO:  FIX THIS.

        match P::FIELD_TYPE {
            FieldType::Bn254 => {
                let syscall_code_key = match syscall_code {
                    SyscallCode::BN254_FP_ADD
                    | SyscallCode::BN254_FP_SUB
                    | SyscallCode::BN254_FP_MUL => SyscallCode::BN254_FP_ADD,
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
                    PrecompileEvent::Bn254Fp(event),
                );
            }
            FieldType::Bls12381 => {
                let syscall_code_key = match syscall_code {
                    SyscallCode::BLS12381_FP_ADD
                    | SyscallCode::BLS12381_FP_SUB
                    | SyscallCode::BLS12381_FP_MUL => SyscallCode::BLS12381_FP_ADD,
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
                    PrecompileEvent::Bls12381Fp(event),
                );
            }
        }

        None
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}
