use num::BigUint;
use sp1_curves::{
    params::NumWords,
    weierstrass::{FieldType, FpOpField},
};
use std::marker::PhantomData;
use typenum::Unsigned;

use crate::{
    events::{FieldOperation, FpOpEvent},
    syscalls::{Syscall, SyscallContext},
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
    fn execute(&self, rt: &mut SyscallContext, arg1: u32, arg2: u32) -> Option<u32> {
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

        let lookup_id = rt.syscall_lookup_id as usize;
        let shard = rt.current_shard();
        let channel = rt.current_channel();
        match P::FIELD_TYPE {
            FieldType::Bn254 => {
                rt.record_mut().bn254_fp_events.push(FpOpEvent {
                    lookup_id,
                    shard,
                    channel,
                    clk,
                    x_ptr,
                    x,
                    y_ptr,
                    y,
                    op: self.op,
                    x_memory_records,
                    y_memory_records,
                });
            }
            FieldType::Bls12381 => {
                rt.record_mut().bls12381_fp_events.push(FpOpEvent {
                    lookup_id,
                    shard,
                    channel,
                    clk,
                    x_ptr,
                    x,
                    y_ptr,
                    y,
                    op: self.op,
                    x_memory_records,
                    y_memory_records,
                });
            }
        }

        None
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}

// impl<P: FpOpField> FpOpSyscall<P> {
//     pub const fn new(op: FieldOperation) -> Self {
//         Self { op, _marker: PhantomData }
//     }
// }

// impl<P: FpOpField> FpOpChip<P> {
//     pub const fn new() -> Self {
//         Self { _marker: PhantomData }
//     }

//     #[allow(clippy::too_many_arguments)]
//     fn populate_field_ops<F: PrimeField32>(
//         blu_events: &mut Vec<ByteLookupEvent>,
//         shard: u32,
//         channel: u8,
//         cols: &mut FpOpCols<F, P>,
//         p: BigUint,
//         q: BigUint,
//         op: FieldOperation,
//     ) {
//         let modulus_bytes = P::MODULUS;
//         let modulus = BigUint::from_bytes_le(modulus_bytes);
//         cols.output.populate_with_modulus(blu_events, shard, channel, &p, &q, &modulus, op);
//     }
// }

// impl<F: PrimeField32, P: FpOpField> MachineAir<F> for FpOpChip<P> {
//     type Record = ExecutionRecord;

//     type Program = Program;

//     fn name(&self) -> String {
//         match P::FIELD_TYPE {
//             FieldType::Bn254 => "Bn254FpOpAssign".to_string(),
//             FieldType::Bls12381 => "Bls12381FpOpAssign".to_string(),
//         }
//     }

//     fn generate_trace(&self, input: &Self::Record, output: &mut Self::Record) ->
// RowMajorMatrix<F> {         let events = match P::FIELD_TYPE {
//             FieldType::Bn254 => &input.bn254_fp_events,
//             FieldType::Bls12381 => &input.bls12381_fp_events,
//         };

//         let mut rows = Vec::new();
//         let mut new_byte_lookup_events = Vec::new();

//         for i in 0..events.len() {
//             let event = &events[i];

//             let mut row = vec![F::zero(); num_fp_cols::<P>()];
//             let cols: &mut FpOpCols<F, P> = row.as_mut_slice().borrow_mut();

//             let modulus = &BigUint::from_bytes_le(P::MODULUS);
//             let p = BigUint::from_bytes_le(&words_to_bytes_le_vec(&event.x)) % modulus;
//             let q = BigUint::from_bytes_le(&words_to_bytes_le_vec(&event.y)) % modulus;

//             cols.is_add = F::from_canonical_u8((event.op == FieldOperation::Add) as u8);
//             cols.is_sub = F::from_canonical_u8((event.op == FieldOperation::Sub) as u8);
//             cols.is_mul = F::from_canonical_u8((event.op == FieldOperation::Mul) as u8);
//             cols.is_real = F::one();
//             cols.shard = F::from_canonical_u32(event.shard);
//             cols.channel = F::from_canonical_u8(event.channel);
//             cols.clk = F::from_canonical_u32(event.clk);
//             cols.x_ptr = F::from_canonical_u32(event.x_ptr);
//             cols.y_ptr = F::from_canonical_u32(event.y_ptr);

//             Self::populate_field_ops(
//                 &mut new_byte_lookup_events,
//                 event.shard,
//                 event.channel,
//                 cols,
//                 p,
//                 q,
//                 event.op,
//             );

//             // Populate the memory access columns.
//             for i in 0..cols.y_access.len() {
//                 cols.y_access[i].populate(
//                     event.channel,
//                     event.y_memory_records[i],
//                     &mut new_byte_lookup_events,
//                 );
//             }
//             for i in 0..cols.x_access.len() {
//                 cols.x_access[i].populate(
//                     event.channel,
//                     event.x_memory_records[i],
//                     &mut new_byte_lookup_events,
//                 );
//             }
//             rows.push(row)
//         }

//         output.add_byte_lookup_events(new_byte_lookup_events);

//         pad_rows(&mut rows, || {
//             let mut row = vec![F::zero(); num_fp_cols::<P>()];
//             let cols: &mut FpOpCols<F, P> = row.as_mut_slice().borrow_mut();
//             let zero = BigUint::zero();
//             cols.is_add = F::from_canonical_u8(1);
//             Self::populate_field_ops(
//                 &mut vec![],
//                 0,
//                 0,
//                 cols,
//                 zero.clone(),
//                 zero,
//                 FieldOperation::Add,
//             );
//             row
//         });

//         // Convert the trace to a row major matrix.
//         let mut trace =
//             RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(),
// num_fp_cols::<P>());

//         // Write the nonces to the trace.
//         for i in 0..trace.height() {
//             let cols: &mut FpOpCols<F, P> =
//                 trace.values[i * num_fp_cols::<P>()..(i + 1) * num_fp_cols::<P>()].borrow_mut();
//             cols.nonce = F::from_canonical_usize(i);
//         }

//         trace
//     }

//     fn included(&self, shard: &Self::Record) -> bool {
//         match P::FIELD_TYPE {
//             FieldType::Bn254 => !shard.bn254_fp_events.is_empty(),
//             FieldType::Bls12381 => !shard.bls12381_fp_events.is_empty(),
//         }
//     }
// }

// impl<F, P: FpOpField> BaseAir<F> for FpOpChip<P> {
//     fn width(&self) -> usize {
//         num_fp_cols::<P>()
//     }
// }

// impl<AB, P: FpOpField> Air<AB> for FpOpChip<P>
// where
//     AB: SP1AirBuilder,
//     Limbs<AB::Var, <P as NumLimbs>::Limbs>: Copy,
// {
//     fn eval(&self, builder: &mut AB) {
//         let main = builder.main();
//         let local = main.row_slice(0);
//         let local: &FpOpCols<AB::Var, P> = (*local).borrow();

//         // Check that operations flags are boolean.
//         builder.assert_bool(local.is_add);
//         builder.assert_bool(local.is_sub);
//         builder.assert_bool(local.is_mul);
//         // Check that only one of them is set.
//         builder.assert_eq(local.is_add + local.is_sub + local.is_mul, AB::Expr::one());

//         let p = limbs_from_prev_access(&local.x_access);
//         let q = limbs_from_prev_access(&local.y_access);

//         let modulus_coeffs =
//             P::MODULUS.iter().map(|&limbs| AB::Expr::from_canonical_u8(limbs)).collect_vec();
//         let p_modulus = Polynomial::from_coefficients(&modulus_coeffs);

//         local.output.eval_variable(
//             builder,
//             &p,
//             &q,
//             &p_modulus,
//             local.is_add,
//             local.is_sub,
//             local.is_mul,
//             AB::F::zero(),
//             local.shard,
//             local.channel,
//             local.is_real,
//         );

//         builder
//             .when(local.is_real)
//             .assert_all_eq(local.output.result, value_as_limbs(&local.x_access));

//         builder.eval_memory_access_slice(
//             local.shard,
//             local.channel,
//             local.clk.into(),
//             local.y_ptr,
//             &local.y_access,
//             local.is_real,
//         );
//         builder.eval_memory_access_slice(
//             local.shard,
//             local.channel,
//             local.clk + AB::F::from_canonical_u32(1), // We read p at +1 since p, q could be the
// same.             local.x_ptr,
//             &local.x_access,
//             local.is_real,
//         );

//         // Select the correct syscall id based on the operation flags.
//         //
//         // *Remark*: If support for division is added, we will need to add the division syscall
// id.         let (add_syscall_id, sub_syscall_id, mul_syscall_id) = match P::FIELD_TYPE {
//             FieldType::Bn254 => (
//                 AB::F::from_canonical_u32(SyscallCode::BN254_FP_ADD.syscall_id()),
//                 AB::F::from_canonical_u32(SyscallCode::BN254_FP_SUB.syscall_id()),
//                 AB::F::from_canonical_u32(SyscallCode::BN254_FP_MUL.syscall_id()),
//             ),
//             FieldType::Bls12381 => (
//                 AB::F::from_canonical_u32(SyscallCode::BLS12381_FP_ADD.syscall_id()),
//                 AB::F::from_canonical_u32(SyscallCode::BLS12381_FP_SUB.syscall_id()),
//                 AB::F::from_canonical_u32(SyscallCode::BLS12381_FP_MUL.syscall_id()),
//             ),
//         };
//         let syscall_id_felt = local.is_add * add_syscall_id
//             + local.is_sub * sub_syscall_id
//             + local.is_mul * mul_syscall_id;

//         builder.receive_syscall(
//             local.shard,
//             local.channel,
//             local.clk,
//             local.nonce,
//             syscall_id_felt,
//             local.x_ptr,
//             local.y_ptr,
//             local.is_real,
//         );
//     }
// }
