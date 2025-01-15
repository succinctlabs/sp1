use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use std::{fmt::Debug, marker::PhantomData};

use crate::{air::MemoryAirBuilder, operations::field::range::FieldLtCols, utils::zeroed_f_vec};
use generic_array::GenericArray;
use num::{BigUint, One, Zero};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::{ParallelBridge, ParallelIterator, ParallelSlice};
use sp1_core_executor::{
    events::{
        ByteLookupEvent, ByteRecord, EllipticCurveAddEvent, FieldOperation, MemoryReadRecord,
        PrecompileEvent, SyscallEvent,
    },
    syscalls::SyscallCode,
    ExecutionRecord, Program,
};
use sp1_curves::{
    params::{FieldParameters, Limbs, NumLimbs, NumWords},
    weierstrass::WeierstrassParameters,
    AffinePoint, CurveType, EllipticCurve,
};
use sp1_derive::AlignedBorrow;
use sp1_stark::air::{InteractionScope, MachineAir, Polynomial, SP1AirBuilder};
use typenum::Unsigned;

use crate::{
    memory::{MemoryCols, MemoryReadCols, MemoryWriteCols},
    operations::field::field_op::FieldOpCols,
    utils::limbs_from_prev_access,
};

pub const fn num_weierstrass_add_cols<P: FieldParameters + NumWords>() -> usize {
    size_of::<WeierstrassAddAssignCols<u8, P>>()
}

/// A set of columns to compute `WeierstrassAdd` that add two points on a Weierstrass curve.
///
/// Right now the number of limbs is assumed to be a constant, although this could be macro-ed or
/// made generic in the future.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct WeierstrassAddAssignCols<T, P: FieldParameters + NumWords> {
    pub is_real: T,
    pub shard: T,
    pub clk: T,
    pub p_ptr: T,
    pub q_ptr: T,
    pub p_access: GenericArray<MemoryWriteCols<T>, P::WordsCurvePoint>,
    pub q_access: GenericArray<MemoryReadCols<T>, P::WordsCurvePoint>,
    pub(crate) slope_denominator: FieldOpCols<T, P>,
    pub(crate) inverse_check: FieldOpCols<T, P>,
    pub(crate) slope_numerator: FieldOpCols<T, P>,
    pub(crate) slope: FieldOpCols<T, P>,
    pub(crate) slope_squared: FieldOpCols<T, P>,
    pub(crate) p_x_plus_q_x: FieldOpCols<T, P>,
    pub(crate) x3_ins: FieldOpCols<T, P>,
    pub(crate) p_x_minus_x: FieldOpCols<T, P>,
    pub(crate) y3_ins: FieldOpCols<T, P>,
    pub(crate) slope_times_p_x_minus_x: FieldOpCols<T, P>,
    pub(crate) x3_range: FieldLtCols<T, P>,
    pub(crate) y3_range: FieldLtCols<T, P>,
}

#[derive(Default)]
pub struct WeierstrassAddAssignChip<E> {
    _marker: PhantomData<E>,
}

impl<E: EllipticCurve> WeierstrassAddAssignChip<E> {
    pub const fn new() -> Self {
        Self { _marker: PhantomData }
    }

    #[allow(clippy::too_many_arguments)]
    fn populate_field_ops<F: PrimeField32>(
        blu_events: &mut Vec<ByteLookupEvent>,
        cols: &mut WeierstrassAddAssignCols<F, E::BaseField>,
        p_x: BigUint,
        p_y: BigUint,
        q_x: BigUint,
        q_y: BigUint,
    ) {
        // This populates necessary field operations to calculate the addition of two points on a
        // Weierstrass curve.

        // slope = (q.y - p.y) / (q.x - p.x).
        let slope = {
            let slope_numerator =
                cols.slope_numerator.populate(blu_events, &q_y, &p_y, FieldOperation::Sub);

            let slope_denominator =
                cols.slope_denominator.populate(blu_events, &q_x, &p_x, FieldOperation::Sub);

            cols.inverse_check.populate(
                blu_events,
                &BigUint::one(),
                &slope_denominator,
                FieldOperation::Div,
            );

            cols.slope.populate(
                blu_events,
                &slope_numerator,
                &slope_denominator,
                FieldOperation::Div,
            )
        };

        // x = slope * slope - (p.x + q.x).
        let x = {
            let slope_squared =
                cols.slope_squared.populate(blu_events, &slope, &slope, FieldOperation::Mul);
            let p_x_plus_q_x =
                cols.p_x_plus_q_x.populate(blu_events, &p_x, &q_x, FieldOperation::Add);
            let x3 = cols.x3_ins.populate(
                blu_events,
                &slope_squared,
                &p_x_plus_q_x,
                FieldOperation::Sub,
            );
            cols.x3_range.populate(blu_events, &x3, &E::BaseField::modulus());
            x3
        };

        // y = slope * (p.x - x_3n) - p.y.
        {
            let p_x_minus_x = cols.p_x_minus_x.populate(blu_events, &p_x, &x, FieldOperation::Sub);
            let slope_times_p_x_minus_x = cols.slope_times_p_x_minus_x.populate(
                blu_events,
                &slope,
                &p_x_minus_x,
                FieldOperation::Mul,
            );
            let y3 = cols.y3_ins.populate(
                blu_events,
                &slope_times_p_x_minus_x,
                &p_y,
                FieldOperation::Sub,
            );
            cols.y3_range.populate(blu_events, &y3, &E::BaseField::modulus());
        }
    }
}

impl<F: PrimeField32, E: EllipticCurve + WeierstrassParameters> MachineAir<F>
    for WeierstrassAddAssignChip<E>
{
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => "Secp256k1AddAssign".to_string(),
            CurveType::Secp256r1 => "Secp256r1AddAssign".to_string(),
            CurveType::Bn254 => "Bn254AddAssign".to_string(),
            CurveType::Bls12381 => "Bls12381AddAssign".to_string(),
            _ => panic!("Unsupported curve"),
        }
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let events = match E::CURVE_TYPE {
            CurveType::Secp256k1 => &input.get_precompile_events(SyscallCode::SECP256K1_ADD),
            CurveType::Secp256r1 => &input.get_precompile_events(SyscallCode::SECP256R1_ADD),
            CurveType::Bn254 => &input.get_precompile_events(SyscallCode::BN254_ADD),
            CurveType::Bls12381 => &input.get_precompile_events(SyscallCode::BLS12381_ADD),
            _ => panic!("Unsupported curve"),
        };

        let num_cols = num_weierstrass_add_cols::<E::BaseField>();
        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        let blu_events: Vec<Vec<ByteLookupEvent>> = events
            .par_chunks(chunk_size)
            .map(|ops: &[(SyscallEvent, PrecompileEvent)]| {
                // The blu map stores shard -> map(byte lookup event -> multiplicity).
                let mut blu = Vec::new();
                ops.iter().for_each(|(_, op)| match op {
                    PrecompileEvent::Secp256k1Add(event)
                    | PrecompileEvent::Secp256r1Add(event)
                    | PrecompileEvent::Bn254Add(event)
                    | PrecompileEvent::Bls12381Add(event) => {
                        let mut row = zeroed_f_vec(num_cols);
                        let cols: &mut WeierstrassAddAssignCols<F, E::BaseField> =
                            row.as_mut_slice().borrow_mut();
                        Self::populate_row(event, cols, &mut blu);
                    }
                    _ => unreachable!(),
                });
                blu
            })
            .collect();

        for blu in blu_events {
            output.add_byte_lookup_events(blu);
        }
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let events = match E::CURVE_TYPE {
            CurveType::Secp256k1 => input.get_precompile_events(SyscallCode::SECP256K1_ADD),
            CurveType::Secp256r1 => input.get_precompile_events(SyscallCode::SECP256R1_ADD),
            CurveType::Bn254 => input.get_precompile_events(SyscallCode::BN254_ADD),
            CurveType::Bls12381 => input.get_precompile_events(SyscallCode::BLS12381_ADD),
            _ => panic!("Unsupported curve"),
        };

        let num_cols = num_weierstrass_add_cols::<E::BaseField>();
        let num_rows = input
            .fixed_log2_rows::<F, _>(self)
            .map(|x| 1 << x)
            .unwrap_or(std::cmp::max(events.len().next_power_of_two(), 4));
        let mut values = zeroed_f_vec(num_rows * num_cols);
        let chunk_size = 64;

        let mut dummy_row = zeroed_f_vec(num_weierstrass_add_cols::<E::BaseField>());
        let cols: &mut WeierstrassAddAssignCols<F, E::BaseField> =
            dummy_row.as_mut_slice().borrow_mut();
        let num_words_field_element = E::BaseField::NB_LIMBS / 4;
        let dummy_memory_record =
            MemoryReadRecord { value: 1, shard: 0, timestamp: 1, prev_shard: 0, prev_timestamp: 0 };
        let zero = BigUint::zero();
        let one = BigUint::one();
        cols.q_access[0].populate(dummy_memory_record, &mut vec![]);
        cols.q_access[num_words_field_element].populate(dummy_memory_record, &mut vec![]);
        Self::populate_field_ops(&mut vec![], cols, zero.clone(), zero, one.clone(), one);

        values.chunks_mut(chunk_size * num_cols).enumerate().par_bridge().for_each(|(i, rows)| {
            rows.chunks_mut(num_cols).enumerate().for_each(|(j, row)| {
                let idx = i * chunk_size + j;
                if idx < events.len() {
                    let mut new_byte_lookup_events = Vec::new();
                    let cols: &mut WeierstrassAddAssignCols<F, E::BaseField> = row.borrow_mut();
                    match &events[idx].1 {
                        PrecompileEvent::Secp256k1Add(event)
                        | PrecompileEvent::Secp256r1Add(event)
                        | PrecompileEvent::Bn254Add(event)
                        | PrecompileEvent::Bls12381Add(event) => {
                            Self::populate_row(event, cols, &mut new_byte_lookup_events);
                        }
                        _ => unreachable!(),
                    }
                } else {
                    row.copy_from_slice(&dummy_row);
                }
            });
        });

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, num_weierstrass_add_cols::<E::BaseField>())
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            match E::CURVE_TYPE {
                CurveType::Secp256k1 => {
                    !shard.get_precompile_events(SyscallCode::SECP256K1_ADD).is_empty()
                }
                CurveType::Secp256r1 => {
                    !shard.get_precompile_events(SyscallCode::SECP256R1_ADD).is_empty()
                }
                CurveType::Bn254 => !shard.get_precompile_events(SyscallCode::BN254_ADD).is_empty(),
                CurveType::Bls12381 => {
                    !shard.get_precompile_events(SyscallCode::BLS12381_ADD).is_empty()
                }
                _ => panic!("Unsupported curve"),
            }
        }
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl<F, E: EllipticCurve> BaseAir<F> for WeierstrassAddAssignChip<E> {
    fn width(&self) -> usize {
        num_weierstrass_add_cols::<E::BaseField>()
    }
}

impl<AB, E: EllipticCurve> Air<AB> for WeierstrassAddAssignChip<E>
where
    AB: SP1AirBuilder,
    Limbs<AB::Var, <E::BaseField as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &WeierstrassAddAssignCols<AB::Var, E::BaseField> = (*local).borrow();

        let num_words_field_element = <E::BaseField as NumLimbs>::Limbs::USIZE / 4;

        let p_x = limbs_from_prev_access(&local.p_access[0..num_words_field_element]);
        let p_y = limbs_from_prev_access(&local.p_access[num_words_field_element..]);

        let q_x = limbs_from_prev_access(&local.q_access[0..num_words_field_element]);
        let q_y = limbs_from_prev_access(&local.q_access[num_words_field_element..]);

        // slope = (q.y - p.y) / (q.x - p.x).
        let slope = {
            local.slope_numerator.eval(builder, &q_y, &p_y, FieldOperation::Sub, local.is_real);

            local.slope_denominator.eval(builder, &q_x, &p_x, FieldOperation::Sub, local.is_real);

            // We check that (q.x - p.x) is non-zero in the base field, by computing 1 / (q.x - p.x).
            let mut coeff_1 = Vec::new();
            coeff_1.resize(<E::BaseField as NumLimbs>::Limbs::USIZE, AB::Expr::zero());
            coeff_1[0] = AB::Expr::one();
            let one_polynomial = Polynomial::from_coefficients(&coeff_1);

            local.inverse_check.eval(
                builder,
                &one_polynomial,
                &local.slope_denominator.result,
                FieldOperation::Div,
                local.is_real,
            );

            local.slope.eval(
                builder,
                &local.slope_numerator.result,
                &local.slope_denominator.result,
                FieldOperation::Div,
                local.is_real,
            );

            &local.slope.result
        };

        // x = slope * slope - self.x - other.x.
        let x = {
            local.slope_squared.eval(builder, slope, slope, FieldOperation::Mul, local.is_real);

            local.p_x_plus_q_x.eval(builder, &p_x, &q_x, FieldOperation::Add, local.is_real);

            local.x3_ins.eval(
                builder,
                &local.slope_squared.result,
                &local.p_x_plus_q_x.result,
                FieldOperation::Sub,
                local.is_real,
            );

            &local.x3_ins.result
        };

        // y = slope * (p.x - x_3n) - q.y.
        {
            local.p_x_minus_x.eval(builder, &p_x, x, FieldOperation::Sub, local.is_real);

            local.slope_times_p_x_minus_x.eval(
                builder,
                slope,
                &local.p_x_minus_x.result,
                FieldOperation::Mul,
                local.is_real,
            );

            local.y3_ins.eval(
                builder,
                &local.slope_times_p_x_minus_x.result,
                &p_y,
                FieldOperation::Sub,
                local.is_real,
            );
        }

        let modulus = E::BaseField::to_limbs_field::<AB::Expr, AB::F>(&E::BaseField::modulus());
        local.x3_range.eval(builder, &local.x3_ins.result, &modulus, local.is_real);
        local.y3_range.eval(builder, &local.y3_ins.result, &modulus, local.is_real);

        // Constraint self.p_access.value = [self.x3_ins.result, self.y3_ins.result]. This is to
        // ensure that p_access is updated with the new value.
        for i in 0..E::BaseField::NB_LIMBS {
            builder
                .when(local.is_real)
                .assert_eq(local.x3_ins.result[i], local.p_access[i / 4].value()[i % 4]);
            builder.when(local.is_real).assert_eq(
                local.y3_ins.result[i],
                local.p_access[num_words_field_element + i / 4].value()[i % 4],
            );
        }

        builder.eval_memory_access_slice(
            local.shard,
            local.clk.into(),
            local.q_ptr,
            &local.q_access,
            local.is_real,
        );
        builder.eval_memory_access_slice(
            local.shard,
            local.clk + AB::F::from_canonical_u32(1), /* We read p at +1 since p, q could be the
                                                       * same. */
            local.p_ptr,
            &local.p_access,
            local.is_real,
        );

        // Fetch the syscall id for the curve type.
        let syscall_id_felt = match E::CURVE_TYPE {
            CurveType::Secp256k1 => {
                AB::F::from_canonical_u32(SyscallCode::SECP256K1_ADD.syscall_id())
            }
            CurveType::Secp256r1 => {
                AB::F::from_canonical_u32(SyscallCode::SECP256R1_ADD.syscall_id())
            }
            CurveType::Bn254 => AB::F::from_canonical_u32(SyscallCode::BN254_ADD.syscall_id()),
            CurveType::Bls12381 => {
                AB::F::from_canonical_u32(SyscallCode::BLS12381_ADD.syscall_id())
            }
            _ => panic!("Unsupported curve"),
        };

        builder.receive_syscall(
            local.shard,
            local.clk,
            syscall_id_felt,
            local.p_ptr,
            local.q_ptr,
            local.is_real,
            InteractionScope::Local,
        );
    }
}

impl<E: EllipticCurve> WeierstrassAddAssignChip<E> {
    pub fn populate_row<F: PrimeField32>(
        event: &EllipticCurveAddEvent,
        cols: &mut WeierstrassAddAssignCols<F, E::BaseField>,
        new_byte_lookup_events: &mut Vec<ByteLookupEvent>,
    ) {
        // Decode affine points.
        let p = &event.p;
        let q = &event.q;
        let p = AffinePoint::<E>::from_words_le(p);
        let (p_x, p_y) = (p.x, p.y);
        let q = AffinePoint::<E>::from_words_le(q);
        let (q_x, q_y) = (q.x, q.y);

        // Populate basic columns.
        cols.is_real = F::one();
        cols.shard = F::from_canonical_u32(event.shard);
        cols.clk = F::from_canonical_u32(event.clk);
        cols.p_ptr = F::from_canonical_u32(event.p_ptr);
        cols.q_ptr = F::from_canonical_u32(event.q_ptr);

        Self::populate_field_ops(new_byte_lookup_events, cols, p_x, p_y, q_x, q_y);

        // Populate the memory access columns.
        for i in 0..cols.q_access.len() {
            cols.q_access[i].populate(event.q_memory_records[i], new_byte_lookup_events);
        }
        for i in 0..cols.p_access.len() {
            cols.p_access[i].populate(event.p_memory_records[i], new_byte_lookup_events);
        }
    }
}

#[cfg(test)]
mod tests {

    use sp1_core_executor::Program;
    use sp1_stark::CpuProver;
    use test_artifacts::{
        BLS12381_ADD_ELF, BLS12381_DOUBLE_ELF, BLS12381_MUL_ELF, BN254_ADD_ELF, BN254_MUL_ELF,
        SECP256K1_ADD_ELF, SECP256K1_MUL_ELF, SECP256R1_ADD_ELF,
    };

    use crate::{
        io::SP1Stdin,
        utils::{run_test, setup_logger},
    };

    #[test]
    fn test_secp256k1_add_simple() {
        setup_logger();
        let program = Program::from(SECP256K1_ADD_ELF).unwrap();
        let stdin = SP1Stdin::new();
        run_test::<CpuProver<_, _>>(program, stdin).unwrap();
    }

    #[test]
    fn test_secp256r1_add_simple() {
        setup_logger();
        let program = Program::from(SECP256R1_ADD_ELF).unwrap();
        let stdin = SP1Stdin::new();
        run_test::<CpuProver<_, _>>(program, stdin).unwrap();
    }

    #[test]
    fn test_bn254_add_simple() {
        setup_logger();
        let program = Program::from(BN254_ADD_ELF).unwrap();
        let stdin = SP1Stdin::new();
        run_test::<CpuProver<_, _>>(program, stdin).unwrap();
    }

    #[test]
    fn test_bn254_mul_simple() {
        setup_logger();
        let program = Program::from(BN254_MUL_ELF).unwrap();
        let stdin = SP1Stdin::new();
        run_test::<CpuProver<_, _>>(program, stdin).unwrap();
    }

    #[test]
    fn test_secp256k1_mul_simple() {
        setup_logger();
        let program = Program::from(SECP256K1_MUL_ELF).unwrap();
        let stdin = SP1Stdin::new();
        run_test::<CpuProver<_, _>>(program, stdin).unwrap();
    }

    #[test]
    fn test_bls12381_add_simple() {
        setup_logger();
        let program = Program::from(BLS12381_ADD_ELF).unwrap();
        let stdin = SP1Stdin::new();
        run_test::<CpuProver<_, _>>(program, stdin).unwrap();
    }

    #[test]
    fn test_bls12381_double_simple() {
        setup_logger();
        let program = Program::from(BLS12381_DOUBLE_ELF).unwrap();
        let stdin = SP1Stdin::new();
        run_test::<CpuProver<_, _>>(program, stdin).unwrap();
    }

    #[test]
    fn test_bls12381_mul_simple() {
        setup_logger();
        let program = Program::from(BLS12381_MUL_ELF).unwrap();
        let stdin = SP1Stdin::new();
        run_test::<CpuProver<_, _>>(program, stdin).unwrap();
    }
}
