use crate::{
    air::SP1CoreAirBuilder,
    memory::MemoryAccessColsU8,
    operations::{
        field::{field_op::FieldOpCols, range::FieldLtCols},
        AddrAddOperation, SyscallAddrOperation,
    },
    utils::{limbs_to_words, next_multiple_of_32, zeroed_f_vec},
};
use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use generic_array::GenericArray;
use itertools::Itertools;
use num::{BigUint, One, Zero};
use slop_air::{Air, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use slop_maybe_rayon::prelude::{ParallelBridge, ParallelIterator, ParallelSlice};
use sp1_core_executor::{
    events::{
        ByteLookupEvent, ByteRecord, EllipticCurveAddEvent, FieldOperation, MemoryReadRecord,
        MemoryRecordEnum, PrecompileEvent, SyscallEvent,
    },
    ExecutionRecord, Program, SyscallCode,
};
use sp1_curves::{
    params::{FieldParameters, Limbs, NumLimbs, NumWords},
    weierstrass::WeierstrassParameters,
    AffinePoint, CurveType, EllipticCurve,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{
    air::{InteractionScope, MachineAir},
    Word,
};
use sp1_primitives::polynomial::Polynomial;
use std::{fmt::Debug, marker::PhantomData, mem::MaybeUninit};
use typenum::Unsigned;

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
    pub clk_high: T,
    pub clk_low: T,
    pub p_ptr: SyscallAddrOperation<T>,
    pub q_ptr: SyscallAddrOperation<T>,
    pub p_addrs: GenericArray<AddrAddOperation<T>, P::WordsCurvePoint>,
    pub q_addrs: GenericArray<AddrAddOperation<T>, P::WordsCurvePoint>,
    pub p_access: GenericArray<MemoryAccessColsU8<T>, P::WordsCurvePoint>,
    pub q_access: GenericArray<MemoryAccessColsU8<T>, P::WordsCurvePoint>,
    pub slope_denominator: FieldOpCols<T, P>,
    pub inverse_check: FieldOpCols<T, P>,
    pub slope_numerator: FieldOpCols<T, P>,
    pub slope: FieldOpCols<T, P>,
    pub slope_squared: FieldOpCols<T, P>,
    pub p_x_plus_q_x: FieldOpCols<T, P>,
    pub x3_ins: FieldOpCols<T, P>,
    pub p_x_minus_x: FieldOpCols<T, P>,
    pub y3_ins: FieldOpCols<T, P>,
    pub slope_times_p_x_minus_x: FieldOpCols<T, P>,
    pub x3_range: FieldLtCols<T, P>,
    pub y3_range: FieldLtCols<T, P>,
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

    fn name(&self) -> &'static str {
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => "Secp256k1AddAssign",
            CurveType::Secp256r1 => "Secp256r1AddAssign",
            CurveType::Bn254 => "Bn254AddAssign",
            CurveType::Bls12381 => "Bls12381AddAssign",
            _ => panic!("Unsupported curve"),
        }
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = match E::CURVE_TYPE {
            CurveType::Secp256k1 => input.get_precompile_events(SyscallCode::SECP256K1_ADD).len(),
            CurveType::Secp256r1 => input.get_precompile_events(SyscallCode::SECP256R1_ADD).len(),
            CurveType::Bn254 => input.get_precompile_events(SyscallCode::BN254_ADD).len(),
            CurveType::Bls12381 => input.get_precompile_events(SyscallCode::BLS12381_ADD).len(),
            _ => panic!("Unsupported curve"),
        };
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_multiple_of_32(nb_rows, size_log2);
        Some(padded_nb_rows)
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
                        Self::populate_row(
                            event,
                            cols,
                            input.public_values.is_untrusted_programs_enabled,
                            &mut blu,
                        );
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

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        let padded_nb_rows =
            <WeierstrassAddAssignChip<E> as MachineAir<F>>::num_rows(self, input).unwrap();
        let events = match E::CURVE_TYPE {
            CurveType::Secp256k1 => input.get_precompile_events(SyscallCode::SECP256K1_ADD),
            CurveType::Secp256r1 => input.get_precompile_events(SyscallCode::SECP256R1_ADD),
            CurveType::Bn254 => input.get_precompile_events(SyscallCode::BN254_ADD),
            CurveType::Bls12381 => input.get_precompile_events(SyscallCode::BLS12381_ADD),
            _ => panic!("Unsupported curve"),
        };

        let num_event_rows = events.len();
        let num_cols = num_weierstrass_add_cols::<E::BaseField>();
        let chunk_size = 64;

        unsafe {
            let padding_start = num_event_rows * num_cols;
            let padding_size = (padded_nb_rows - num_event_rows) * num_cols;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values =
            unsafe { core::slice::from_raw_parts_mut(buffer_ptr, padded_nb_rows * num_cols) };

        let mut dummy_row = zeroed_f_vec(num_weierstrass_add_cols::<E::BaseField>());
        let cols: &mut WeierstrassAddAssignCols<F, E::BaseField> =
            dummy_row.as_mut_slice().borrow_mut();
        let num_words_field_element = E::BaseField::NB_LIMBS / 8;
        let dummy_memory_record = MemoryReadRecord {
            value: 1,
            timestamp: 1,
            prev_timestamp: 0,
            prev_page_prot_record: None,
        };
        let zero = BigUint::zero();
        let one = BigUint::one();
        let dummy_memory_record_enum = MemoryRecordEnum::Read(dummy_memory_record);
        cols.q_access[0].populate(dummy_memory_record_enum, &mut vec![]);
        cols.q_access[num_words_field_element].populate(dummy_memory_record_enum, &mut vec![]);
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
                            Self::populate_row(
                                event,
                                cols,
                                input.public_values.is_untrusted_programs_enabled,
                                &mut new_byte_lookup_events,
                            );
                        }
                        _ => unreachable!(),
                    }
                } else {
                    row.copy_from_slice(&dummy_row);
                }
            });
        });
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
}

impl<F, E: EllipticCurve> BaseAir<F> for WeierstrassAddAssignChip<E> {
    fn width(&self) -> usize {
        num_weierstrass_add_cols::<E::BaseField>()
    }
}

impl<AB, E: EllipticCurve> Air<AB> for WeierstrassAddAssignChip<E>
where
    AB: SP1CoreAirBuilder,
    Limbs<AB::Var, <E::BaseField as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &WeierstrassAddAssignCols<AB::Var, E::BaseField> = (*local).borrow();

        let num_words_field_element = <E::BaseField as NumLimbs>::Limbs::USIZE / 8;

        let p_x_limbs = builder
            .generate_limbs(&local.p_access[0..num_words_field_element], local.is_real.into());
        let p_x: Limbs<AB::Expr, <E::BaseField as NumLimbs>::Limbs> =
            Limbs(p_x_limbs.try_into().expect("failed to convert limbs"));
        let p_y_limbs = builder
            .generate_limbs(&local.p_access[num_words_field_element..], local.is_real.into());
        let p_y: Limbs<AB::Expr, <E::BaseField as NumLimbs>::Limbs> =
            Limbs(p_y_limbs.try_into().expect("failed to convert limbs"));
        let q_x_limbs = builder
            .generate_limbs(&local.q_access[0..num_words_field_element], local.is_real.into());
        let q_x: Limbs<AB::Expr, <E::BaseField as NumLimbs>::Limbs> =
            Limbs(q_x_limbs.try_into().expect("failed to convert limbs"));
        let q_y_limbs = builder
            .generate_limbs(&local.q_access[num_words_field_element..], local.is_real.into());
        let q_y: Limbs<AB::Expr, <E::BaseField as NumLimbs>::Limbs> =
            Limbs(q_y_limbs.try_into().expect("failed to convert limbs"));

        // slope = (q.y - p.y) / (q.x - p.x).
        let slope = {
            local.slope_numerator.eval(builder, &q_y, &p_y, FieldOperation::Sub, local.is_real);
            local.slope_denominator.eval(builder, &q_x, &p_x, FieldOperation::Sub, local.is_real);

            // We check (q.x - p.x) is non-zero in the base field, by computing 1 / (q.x - p.x).
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

        let x3_result_words = limbs_to_words::<AB>(local.x3_ins.result.0.to_vec());
        let y3_result_words = limbs_to_words::<AB>(local.y3_ins.result.0.to_vec());
        let result_words = x3_result_words.into_iter().chain(y3_result_words).collect_vec();

        let p_ptr = SyscallAddrOperation::<AB::F>::eval(
            builder,
            E::NB_LIMBS as u32 * 2,
            local.p_ptr,
            local.is_real.into(),
        );
        let q_ptr = SyscallAddrOperation::<AB::F>::eval(
            builder,
            E::NB_LIMBS as u32 * 2,
            local.q_ptr,
            local.is_real.into(),
        );

        // p_addrs[i] = p_ptr + 8 * i
        for i in 0..local.p_addrs.len() {
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([p_ptr[0].into(), p_ptr[1].into(), p_ptr[2].into(), AB::Expr::zero()]),
                Word::from(8 * i as u64),
                local.p_addrs[i],
                local.is_real.into(),
            );
        }

        // q_addrs[i] = q_ptr + 8 * i
        for i in 0..local.q_addrs.len() {
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([q_ptr[0].into(), q_ptr[1].into(), q_ptr[2].into(), AB::Expr::zero()]),
                Word::from(8 * i as u64),
                local.q_addrs[i],
                local.is_real.into(),
            );
        }

        builder.eval_memory_access_slice_read(
            local.clk_high,
            local.clk_low.into(),
            &local.q_addrs.iter().map(|addr| addr.value.map(Into::into)).collect::<Vec<_>>(),
            &local.q_access.iter().map(|access| access.memory_access).collect_vec(),
            local.is_real,
        );
        builder.eval_memory_access_slice_write(
            local.clk_high,
            local.clk_low + AB::Expr::one(),
            &local.p_addrs.iter().map(|addr| addr.value.map(Into::into)).collect::<Vec<_>>(),
            &local.p_access.iter().map(|access| access.memory_access).collect_vec(),
            result_words,
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
            local.clk_high,
            local.clk_low.into(),
            syscall_id_felt,
            p_ptr.map(Into::into),
            q_ptr.map(Into::into),
            local.is_real,
            InteractionScope::Local,
        );
    }
}

impl<E: EllipticCurve> WeierstrassAddAssignChip<E> {
    pub fn populate_row<F: PrimeField32>(
        event: &EllipticCurveAddEvent,
        cols: &mut WeierstrassAddAssignCols<F, E::BaseField>,
        _page_prot_enabled: u32,
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

        cols.clk_high = F::from_canonical_u32((event.clk >> 24) as u32);
        cols.clk_low = F::from_canonical_u32((event.clk & 0xFFFFFF) as u32);
        cols.p_ptr.populate(new_byte_lookup_events, event.p_ptr, E::NB_LIMBS as u64 * 2);
        cols.q_ptr.populate(new_byte_lookup_events, event.q_ptr, E::NB_LIMBS as u64 * 2);

        Self::populate_field_ops(new_byte_lookup_events, cols, p_x, p_y, q_x, q_y);

        // Populate the memory access columns.
        for i in 0..cols.q_access.len() {
            let record = MemoryRecordEnum::Read(event.q_memory_records[i]);
            cols.q_access[i].populate(record, new_byte_lookup_events);
            cols.q_addrs[i].populate(new_byte_lookup_events, event.q_ptr, 8 * i as u64);
        }
        for i in 0..cols.p_access.len() {
            let record = MemoryRecordEnum::Write(event.p_memory_records[i]);
            cols.p_access[i].populate(record, new_byte_lookup_events);
            cols.p_addrs[i].populate(new_byte_lookup_events, event.p_ptr, 8 * i as u64);
        }
    }
}

#[cfg(test)]
mod tests {

    use std::sync::Arc;

    use sp1_core_executor::Program;
    use test_artifacts::{
        BLS12381_ADD_ELF, BLS12381_DOUBLE_ELF, BLS12381_MUL_ELF, BN254_ADD_ELF, BN254_MUL_ELF,
        SECP256K1_ADD_ELF, SECP256K1_MUL_ELF, SECP256R1_ADD_ELF,
    };

    use crate::{
        io::SP1Stdin,
        utils::{run_test, setup_logger},
    };

    #[tokio::test]
    async fn test_secp256k1_add_simple() {
        setup_logger();
        let program = Arc::new(Program::from(&SECP256K1_ADD_ELF).unwrap());
        let stdin = SP1Stdin::new();
        run_test(program, stdin).await.unwrap();
    }

    #[tokio::test]
    async fn test_secp256r1_add_simple() {
        setup_logger();
        let program = Arc::new(Program::from(&SECP256R1_ADD_ELF).unwrap());
        let stdin = SP1Stdin::new();
        run_test(program, stdin).await.unwrap();
    }

    #[tokio::test]
    async fn test_bn254_add_simple() {
        setup_logger();
        let program = Arc::new(Program::from(&BN254_ADD_ELF).unwrap());
        let stdin = SP1Stdin::new();
        run_test(program, stdin).await.unwrap();
    }

    #[tokio::test]
    async fn test_bn254_mul_simple() {
        setup_logger();
        let program = Arc::new(Program::from(&BN254_MUL_ELF).unwrap());
        let stdin = SP1Stdin::new();
        run_test(program, stdin).await.unwrap();
    }

    #[tokio::test]
    async fn test_secp256k1_mul_simple() {
        setup_logger();
        let program = Arc::new(Program::from(&SECP256K1_MUL_ELF).unwrap());
        let stdin = SP1Stdin::new();
        run_test(program, stdin).await.unwrap();
    }

    #[tokio::test]
    async fn test_bls12381_add_simple() {
        setup_logger();
        let program = Arc::new(Program::from(&BLS12381_ADD_ELF).unwrap());
        let stdin = SP1Stdin::new();
        run_test(program, stdin).await.unwrap();
    }

    #[tokio::test]
    async fn test_bls12381_double_simple() {
        setup_logger();
        let program = Arc::new(Program::from(&BLS12381_DOUBLE_ELF).unwrap());
        let stdin = SP1Stdin::new();
        run_test(program, stdin).await.unwrap();
    }

    #[tokio::test]
    async fn test_bls12381_mul_simple() {
        setup_logger();
        let program = Arc::new(Program::from(&BLS12381_MUL_ELF).unwrap());
        let stdin = SP1Stdin::new();
        run_test(program, stdin).await.unwrap();
    }
}
