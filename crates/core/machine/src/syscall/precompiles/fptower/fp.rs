use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    mem::size_of,
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
    params::{Limbs, NumLimbs},
    weierstrass::{FieldType, FpOpField},
};
use sp1_derive::AlignedBorrow;
use sp1_stark::air::{BaseAirBuilder, InteractionScope, MachineAir, Polynomial, SP1AirBuilder};

use crate::{
    memory::{value_as_limbs, MemoryReadCols, MemoryWriteCols},
    operations::field::field_op::FieldOpCols,
    utils::{limbs_from_prev_access, pad_rows_fixed, words_to_bytes_le_vec},
};

pub const fn num_fp_cols<P: FpOpField>() -> usize {
    size_of::<FpOpCols<u8, P>>()
}

pub struct FpOpChip<P> {
    _marker: PhantomData<P>,
}

/// A set of columns for the FpAdd operation.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct FpOpCols<T, P: FpOpField> {
    pub is_real: T,
    pub shard: T,
    pub nonce: T,
    pub clk: T,
    pub is_add: T,
    pub is_sub: T,
    pub is_mul: T,
    pub x_ptr: T,
    pub y_ptr: T,
    pub x_access: GenericArray<MemoryWriteCols<T>, P::WordsFieldElement>,
    pub y_access: GenericArray<MemoryReadCols<T>, P::WordsFieldElement>,
    pub(crate) output: FieldOpCols<T, P>,
}

impl<P: FpOpField> FpOpChip<P> {
    pub const fn new() -> Self {
        Self { _marker: PhantomData }
    }

    #[allow(clippy::too_many_arguments)]
    fn populate_field_ops<F: PrimeField32>(
        blu_events: &mut Vec<ByteLookupEvent>,
        shard: u32,
        cols: &mut FpOpCols<F, P>,
        p: BigUint,
        q: BigUint,
        op: FieldOperation,
    ) {
        let modulus_bytes = P::MODULUS;
        let modulus = BigUint::from_bytes_le(modulus_bytes);
        cols.output.populate_with_modulus(blu_events, shard, &p, &q, &modulus, op);
    }
}

impl<F: PrimeField32, P: FpOpField> MachineAir<F> for FpOpChip<P> {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        match P::FIELD_TYPE {
            FieldType::Bn254 => "Bn254FpOpAssign".to_string(),
            FieldType::Bls12381 => "Bls12381FpOpAssign".to_string(),
        }
    }

    fn generate_trace(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
        // All the fp events for a given curve are coalesce to the curve's Add operation.  Only retrieve
        // precompile events for that operation.
        // TODO:  Fix this.

        let events = match P::FIELD_TYPE {
            FieldType::Bn254 => input.get_precompile_events(SyscallCode::BN254_FP_ADD).iter(),
            FieldType::Bls12381 => input.get_precompile_events(SyscallCode::BLS12381_FP_ADD).iter(),
        };

        let mut rows = Vec::new();
        let mut new_byte_lookup_events = Vec::new();

        for (_, event) in events {
            let event = match (P::FIELD_TYPE, event) {
                (FieldType::Bn254, PrecompileEvent::Bn254Fp(event)) => event,
                (FieldType::Bls12381, PrecompileEvent::Bls12381Fp(event)) => event,
                _ => unreachable!(),
            };

            let mut row = zeroed_f_vec(num_fp_cols::<P>());
            let cols: &mut FpOpCols<F, P> = row.as_mut_slice().borrow_mut();

            let modulus = &BigUint::from_bytes_le(P::MODULUS);
            let p = BigUint::from_bytes_le(&words_to_bytes_le_vec(&event.x)) % modulus;
            let q = BigUint::from_bytes_le(&words_to_bytes_le_vec(&event.y)) % modulus;

            cols.is_add = F::from_canonical_u8((event.op == FieldOperation::Add) as u8);
            cols.is_sub = F::from_canonical_u8((event.op == FieldOperation::Sub) as u8);
            cols.is_mul = F::from_canonical_u8((event.op == FieldOperation::Mul) as u8);
            cols.is_real = F::one();
            cols.shard = F::from_canonical_u32(event.shard);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.x_ptr = F::from_canonical_u32(event.x_ptr);
            cols.y_ptr = F::from_canonical_u32(event.y_ptr);

            Self::populate_field_ops(
                &mut new_byte_lookup_events,
                event.shard,
                cols,
                p,
                q,
                event.op,
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
                let mut row = zeroed_f_vec(num_fp_cols::<P>());
                let cols: &mut FpOpCols<F, P> = row.as_mut_slice().borrow_mut();
                let zero = BigUint::zero();
                cols.is_add = F::from_canonical_u8(1);
                Self::populate_field_ops(
                    &mut vec![],
                    0,
                    cols,
                    zero.clone(),
                    zero,
                    FieldOperation::Add,
                );
                row
            },
            input.fixed_log2_rows::<F, _>(self),
        );

        // Convert the trace to a row major matrix.
        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), num_fp_cols::<P>());

        // Write the nonces to the trace.
        for i in 0..trace.height() {
            let cols: &mut FpOpCols<F, P> =
                trace.values[i * num_fp_cols::<P>()..(i + 1) * num_fp_cols::<P>()].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        // All the fp events for a given curve are coalesce to the curve's Add operation. Only
        // check for that operation.

        assert!(
            shard.get_precompile_events(SyscallCode::BN254_FP_SUB).is_empty()
                && shard.get_precompile_events(SyscallCode::BN254_FP_MUL).is_empty()
                && shard.get_precompile_events(SyscallCode::BLS12381_FP_SUB).is_empty()
                && shard.get_precompile_events(SyscallCode::BLS12381_FP_MUL).is_empty()
        );

        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            match P::FIELD_TYPE {
                FieldType::Bn254 => {
                    !shard.get_precompile_events(SyscallCode::BN254_FP_ADD).is_empty()
                }
                FieldType::Bls12381 => {
                    !shard.get_precompile_events(SyscallCode::BLS12381_FP_ADD).is_empty()
                }
            }
        }
    }
}

impl<F, P: FpOpField> BaseAir<F> for FpOpChip<P> {
    fn width(&self) -> usize {
        num_fp_cols::<P>()
    }
}

impl<AB, P: FpOpField> Air<AB> for FpOpChip<P>
where
    AB: SP1AirBuilder,
    Limbs<AB::Var, <P as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &FpOpCols<AB::Var, P> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &FpOpCols<AB::Var, P> = (*next).borrow();

        // Check that nonce is incremented.
        builder.when_first_row().assert_zero(local.nonce);
        builder.when_transition().assert_eq(local.nonce + AB::Expr::one(), next.nonce);

        // Check that operations flags are boolean.
        builder.assert_bool(local.is_add);
        builder.assert_bool(local.is_sub);
        builder.assert_bool(local.is_mul);

        // Check that only one of them is set.
        builder.assert_eq(local.is_add + local.is_sub + local.is_mul, AB::Expr::one());

        let p = limbs_from_prev_access(&local.x_access);
        let q = limbs_from_prev_access(&local.y_access);

        let modulus_coeffs =
            P::MODULUS.iter().map(|&limbs| AB::Expr::from_canonical_u8(limbs)).collect_vec();
        let p_modulus = Polynomial::from_coefficients(&modulus_coeffs);

        local.output.eval_variable(
            builder,
            &p,
            &q,
            &p_modulus,
            local.is_add,
            local.is_sub,
            local.is_mul,
            AB::F::zero(),
            local.is_real,
        );

        builder
            .when(local.is_real)
            .assert_all_eq(local.output.result, value_as_limbs(&local.x_access));

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

        // Select the correct syscall id based on the operation flags.
        //
        // *Remark*: If support for division is added, we will need to add the division syscall id.
        let (add_syscall_id, sub_syscall_id, mul_syscall_id) = match P::FIELD_TYPE {
            FieldType::Bn254 => (
                AB::F::from_canonical_u32(SyscallCode::BN254_FP_ADD.syscall_id()),
                AB::F::from_canonical_u32(SyscallCode::BN254_FP_SUB.syscall_id()),
                AB::F::from_canonical_u32(SyscallCode::BN254_FP_MUL.syscall_id()),
            ),
            FieldType::Bls12381 => (
                AB::F::from_canonical_u32(SyscallCode::BLS12381_FP_ADD.syscall_id()),
                AB::F::from_canonical_u32(SyscallCode::BLS12381_FP_SUB.syscall_id()),
                AB::F::from_canonical_u32(SyscallCode::BLS12381_FP_MUL.syscall_id()),
            ),
        };
        let syscall_id_felt = local.is_add * add_syscall_id
            + local.is_sub * sub_syscall_id
            + local.is_mul * mul_syscall_id;

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
