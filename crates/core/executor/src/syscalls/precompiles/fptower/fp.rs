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

        match P::FIELD_TYPE {
            FieldType::Bn254 => {
                rt.record_mut().add_precompile_event(syscall_code, PrecompileEvent::Bn254Fp(event));
            }
            FieldType::Bls12381 => rt
                .record_mut()
                .add_precompile_event(syscall_code, PrecompileEvent::Bls12381Fp(event)),
        }

        None
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}
