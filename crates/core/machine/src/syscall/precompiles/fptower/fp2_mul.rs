use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
};

use crate::{air::MemoryAirBuilder, utils::zeroed_f_vec};
use generic_array::GenericArray;
use itertools::Itertools;
use num::{BigUint, Zero};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord, FieldOperation, PrecompileEvent},
    syscalls::SyscallCode,
    ExecutionRecord, Program,
};
use sp1_curves::{
    params::{FieldParameters, Limbs, NumLimbs, NumWords},
    weierstrass::{FieldType, FpOpField},
};
use sp1_derive::AlignedBorrow;
use sp1_stark::air::{BaseAirBuilder, InteractionScope, MachineAir, Polynomial, SP1AirBuilder};
use std::mem::size_of;
use typenum::Unsigned;

use crate::{
    memory::{value_as_limbs, MemoryReadCols, MemoryWriteCols},
    operations::field::field_op::FieldOpCols,
    utils::{limbs_from_prev_access, pad_rows_fixed, words_to_bytes_le_vec},
};

pub const fn num_fp2_mul_cols<P: FieldParameters + NumWords>() -> usize {
    size_of::<Fp2MulAssignCols<u8, P>>()
}

/// A set of columns for the Fp2Mul operation.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct Fp2MulAssignCols<T, P: FieldParameters + NumWords> {
    pub is_real: T,
    pub shard: T,
    pub nonce: T,
    pub clk: T,
    pub x_ptr: T,
    pub y_ptr: T,
    pub x_access: GenericArray<MemoryWriteCols<T>, P::WordsCurvePoint>,
    pub y_access: GenericArray<MemoryReadCols<T>, P::WordsCurvePoint>,
    pub(crate) a0_mul_b0: FieldOpCols<T, P>,
    pub(crate) a1_mul_b1: FieldOpCols<T, P>,
    pub(crate) a0_mul_b1: FieldOpCols<T, P>,
    pub(crate) a1_mul_b0: FieldOpCols<T, P>,
    pub(crate) c0: FieldOpCols<T, P>,
    pub(crate) c1: FieldOpCols<T, P>,
}

#[derive(Default)]
pub struct Fp2MulAssignChip<P> {
    _marker: PhantomData<P>,
}

impl<P: FpOpField> Fp2MulAssignChip<P> {
    pub const fn new() -> Self {
        Self { _marker: PhantomData }
    }

    #[allow(clippy::too_many_arguments)]
    fn populate_field_ops<F: PrimeField32>(
        blu_events: &mut Vec<ByteLookupEvent>,
        shard: u32,
        cols: &mut Fp2MulAssignCols<F, P>,
        p_x: BigUint,
        p_y: BigUint,
        q_x: BigUint,
        q_y: BigUint,
    ) {
        let modulus_bytes = P::MODULUS;
        let modulus = BigUint::from_bytes_le(modulus_bytes);
        let a0_mul_b0 = cols.a0_mul_b0.populate_with_modulus(
            blu_events,
            shard,
            &p_x,
            &q_x,
            &modulus,
            FieldOperation::Mul,
        );
        let a1_mul_b1 = cols.a1_mul_b1.populate_with_modulus(
            blu_events,
            shard,
            &p_y,
            &q_y,
            &modulus,
            FieldOperation::Mul,
        );
        let a0_mul_b1 = cols.a0_mul_b1.populate_with_modulus(
            blu_events,
            shard,
            &p_x,
            &q_y,
            &modulus,
            FieldOperation::Mul,
        );
        let a1_mul_b0 = cols.a1_mul_b0.populate_with_modulus(
            blu_events,
            shard,
            &p_y,
            &q_x,
            &modulus,
            FieldOperation::Mul,
        );
        cols.c0.populate_with_modulus(
            blu_events,
            shard,
            &a0_mul_b0,
            &a1_mul_b1,
            &modulus,
            FieldOperation::Sub,
        );
        cols.c1.populate_with_modulus(
            blu_events,
            shard,
            &a0_mul_b1,
            &a1_mul_b0,
            &modulus,
            FieldOperation::Add,
        );
    }
}

impl<F: PrimeField32, P: FpOpField> MachineAir<F> for Fp2MulAssignChip<P> {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        match P::FIELD_TYPE {
            FieldType::Bn254 => "Bn254Fp2MulAssign".to_string(),
            FieldType::Bls12381 => "Bls12831Fp2MulAssign".to_string(),
        }
    }

    fn generate_trace(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = match P::FIELD_TYPE {
            FieldType::Bn254 => input.get_precompile_events(SyscallCode::BN254_FP2_MUL),
            FieldType::Bls12381 => input.get_precompile_events(SyscallCode::BLS12381_FP2_MUL),
        };

        let mut rows = Vec::new();
        let mut new_byte_lookup_events = Vec::new();

        for (_, event) in events {
            let event = match (P::FIELD_TYPE, event) {
                (FieldType::Bn254, PrecompileEvent::Bn254Fp2Mul(event)) => event,
                (FieldType::Bls12381, PrecompileEvent::Bls12381Fp2Mul(event)) => event,
                _ => unreachable!(),
            };

            let mut row = zeroed_f_vec(num_fp2_mul_cols::<P>());
            let cols: &mut Fp2MulAssignCols<F, P> = row.as_mut_slice().borrow_mut();

            let p = &event.x;
            let q = &event.y;
            let p_x = BigUint::from_bytes_le(&words_to_bytes_le_vec(&p[..p.len() / 2]));
            let p_y = BigUint::from_bytes_le(&words_to_bytes_le_vec(&p[p.len() / 2..]));
            let q_x = BigUint::from_bytes_le(&words_to_bytes_le_vec(&q[..q.len() / 2]));
            let q_y = BigUint::from_bytes_le(&words_to_bytes_le_vec(&q[q.len() / 2..]));

            cols.is_real = F::one();
            cols.shard = F::from_canonical_u32(event.shard);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.x_ptr = F::from_canonical_u32(event.x_ptr);
            cols.y_ptr = F::from_canonical_u32(event.y_ptr);

            Self::populate_field_ops(
                &mut new_byte_lookup_events,
                event.shard,
                cols,
                p_x,
                p_y,
                q_x,
                q_y,
            );

            // Populate the memory access columns.
            for i in 0..cols.y_access.len() {
                cols.y_access[i].populate(event.y_memory_records[i], &mut new_byte_lookup_events);
            }
            for i in 0..cols.x_access.len() {
                cols.x_access[i].populate(event.x_memory_records[i], &mut new_byte_lookup_events);
            }
            rows.push(row);
        }

        output.add_byte_lookup_events(new_byte_lookup_events);

        pad_rows_fixed(
            &mut rows,
            || {
                let mut row = zeroed_f_vec(num_fp2_mul_cols::<P>());
                let cols: &mut Fp2MulAssignCols<F, P> = row.as_mut_slice().borrow_mut();
                let zero = BigUint::zero();
                Self::populate_field_ops(
                    &mut vec![],
                    0,
                    cols,
                    zero.clone(),
                    zero.clone(),
                    zero.clone(),
                    zero,
                );
                row
            },
            input.fixed_log2_rows::<F, _>(self),
        );

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            num_fp2_mul_cols::<P>(),
        );

        // Write the nonces to the trace.
        for i in 0..trace.height() {
            let cols: &mut Fp2MulAssignCols<F, P> = trace.values
                [i * num_fp2_mul_cols::<P>()..(i + 1) * num_fp2_mul_cols::<P>()]
                .borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            match P::FIELD_TYPE {
                FieldType::Bn254 => {
                    !shard.get_precompile_events(SyscallCode::BN254_FP2_MUL).is_empty()
                }
                FieldType::Bls12381 => {
                    !shard.get_precompile_events(SyscallCode::BLS12381_FP2_MUL).is_empty()
                }
            }
        }
    }
}

impl<F, P: FpOpField> BaseAir<F> for Fp2MulAssignChip<P> {
    fn width(&self) -> usize {
        num_fp2_mul_cols::<P>()
    }
}

impl<AB, P: FpOpField> Air<AB> for Fp2MulAssignChip<P>
where
    AB: SP1AirBuilder,
    Limbs<AB::Var, <P as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Fp2MulAssignCols<AB::Var, P> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &Fp2MulAssignCols<AB::Var, P> = (*next).borrow();

        builder.when_first_row().assert_zero(local.nonce);
        builder.when_transition().assert_eq(local.nonce + AB::Expr::one(), next.nonce);
        let num_words_field_element = <P as NumLimbs>::Limbs::USIZE / 4;

        let p_x = limbs_from_prev_access(&local.x_access[0..num_words_field_element]);
        let p_y = limbs_from_prev_access(&local.x_access[num_words_field_element..]);

        let q_x = limbs_from_prev_access(&local.y_access[0..num_words_field_element]);
        let q_y = limbs_from_prev_access(&local.y_access[num_words_field_element..]);

        let modulus_coeffs =
            P::MODULUS.iter().map(|&limbs| AB::Expr::from_canonical_u8(limbs)).collect_vec();
        let p_modulus = Polynomial::from_coefficients(&modulus_coeffs);

        {
            local.a0_mul_b0.eval_with_modulus(
                builder,
                &p_x,
                &q_x,
                &p_modulus,
                FieldOperation::Mul,
                local.is_real,
            );

            local.a1_mul_b1.eval_with_modulus(
                builder,
                &p_y,
                &q_y,
                &p_modulus,
                FieldOperation::Mul,
                local.is_real,
            );

            local.c0.eval_with_modulus(
                builder,
                &local.a0_mul_b0.result,
                &local.a1_mul_b1.result,
                &p_modulus,
                FieldOperation::Sub,
                local.is_real,
            );
        }

        {
            local.a0_mul_b1.eval_with_modulus(
                builder,
                &p_x,
                &q_y,
                &p_modulus,
                FieldOperation::Mul,
                local.is_real,
            );

            local.a1_mul_b0.eval_with_modulus(
                builder,
                &p_y,
                &q_x,
                &p_modulus,
                FieldOperation::Mul,
                local.is_real,
            );

            local.c1.eval_with_modulus(
                builder,
                &local.a0_mul_b1.result,
                &local.a1_mul_b0.result,
                &p_modulus,
                FieldOperation::Add,
                local.is_real,
            );
        }

        builder.when(local.is_real).assert_all_eq(
            local.c0.result,
            value_as_limbs(&local.x_access[0..num_words_field_element]),
        );
        builder.when(local.is_real).assert_all_eq(
            local.c1.result,
            value_as_limbs(&local.x_access[num_words_field_element..]),
        );

        builder.eval_memory_access_slice(
            local.shard,
            local.clk.into(),
            local.y_ptr,
            &local.y_access,
            local.is_real,
        );
        builder.eval_memory_access_slice(
            local.shard,
            local.clk + AB::F::from_canonical_u32(1), /* We read p at +1 since p, q could be the
                                                       * same. */
            local.x_ptr,
            &local.x_access,
            local.is_real,
        );

        let syscall_id_felt = match P::FIELD_TYPE {
            FieldType::Bn254 => AB::F::from_canonical_u32(SyscallCode::BN254_FP2_MUL.syscall_id()),
            FieldType::Bls12381 => {
                AB::F::from_canonical_u32(SyscallCode::BLS12381_FP2_MUL.syscall_id())
            }
        };

        builder.receive_syscall(
            local.shard,
            local.clk,
            local.nonce,
            syscall_id_felt,
            local.x_ptr,
            local.y_ptr,
            local.is_real,
            InteractionScope::Local,
        );
    }
}
