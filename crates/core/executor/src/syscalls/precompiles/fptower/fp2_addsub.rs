use num::BigUint;
use sp1_curves::{
    params::NumWords,
    weierstrass::{FieldType, FpOpField},
};
use std::marker::PhantomData;
use typenum::Unsigned;

use crate::{
    events::{FieldOperation, Fp2AddSubEvent},
    syscalls::{Syscall, SyscallContext},
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
    fn execute(&self, rt: &mut SyscallContext, arg1: u32, arg2: u32) -> Option<u32> {
        let syscall = rt.syscall;

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

        for i in 0..num_words {
            let addr = y_ptr + i as u32 * 4;
            let local_mem_access = rt.rt.local_memory_access.remove(&addr);

            if let Some(local_mem_access) = local_mem_access {
                rt.rt.record.local_memory_access.push(local_mem_access);
            }
        }

        let (y_memory_records, y) = rt.mr_slice(y_ptr, num_words);

        let mut fp2_addsub_local_mem_access = Vec::new();
        for i in 0..num_words {
            let addr = y_ptr + i as u32 * 4;
            let local_mem_access =
                rt.rt.local_memory_access.remove(&addr).expect("Expected local memory access");

            fp2_addsub_local_mem_access.push(local_mem_access);
        }

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

        for i in 0..result.len() {
            let addr = x_ptr + i as u32 * 4;
            let local_mem_access = rt.rt.local_memory_access.remove(&addr);

            if let Some(local_mem_access) = local_mem_access {
                rt.rt.record.local_memory_access.push(local_mem_access);
            }
        }

        let x_memory_records = rt.mw_slice(x_ptr, &result);

        for i in 0..result.len() {
            let addr = x_ptr + i as u32 * 4;
            let local_mem_access =
                rt.rt.local_memory_access.remove(&addr).expect("Expected local memory access");

            fp2_addsub_local_mem_access.push(local_mem_access);
        }

        let lookup_id = rt.syscall_lookup_id as usize;
        let shard = rt.current_shard();
        let channel = rt.current_channel();
        let op = self.op;
        match P::FIELD_TYPE {
            FieldType::Bn254 => {
                rt.record_mut().bn254_fp2_addsub_events.push(Fp2AddSubEvent {
                    syscall,
                    lookup_id,
                    shard,
                    channel,
                    clk,
                    op,
                    x_ptr,
                    x,
                    y_ptr,
                    y,
                    x_memory_records,
                    y_memory_records,
                    local_mem_access: fp2_addsub_local_mem_access,
                });
            }
            FieldType::Bls12381 => {
                rt.record_mut().bls12381_fp2_addsub_events.push(Fp2AddSubEvent {
                    syscall,
                    lookup_id,
                    shard,
                    channel,
                    clk,
                    op,
                    x_ptr,
                    x,
                    y_ptr,
                    y,
                    x_memory_records,
                    y_memory_records,
                    local_mem_access: fp2_addsub_local_mem_access,
                });
            }
        }
        None
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}
