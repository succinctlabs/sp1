use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    mem::MaybeUninit,
};

use crate::{
    air::SP1CoreAirBuilder,
    memory::MemoryAccessColsU8,
    operations::{
        field::range::FieldLtCols, AddrAddOperation, AddressSlicePageProtOperation,
        SyscallAddrOperation,
    },
    utils::{limbs_to_words, next_multiple_of_32},
};
use crate::{SupervisorMode, TrustMode, UserMode};
use generic_array::GenericArray;
use itertools::Itertools;
use num::{BigUint, Zero};
use slop_air::{Air, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord, FieldOperation, MemoryRecordEnum, PrecompileEvent},
    ExecutionRecord, Program, SyscallCode,
};
use sp1_curves::{
    params::{Limbs, NumLimbs},
    weierstrass::{FieldType, FpOpField},
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{
    air::{InteractionScope, MachineAir},
    Word,
};
use sp1_primitives::{
    consts::{PROT_READ, PROT_WRITE},
    polynomial::Polynomial,
};

use crate::{operations::field::field_op::FieldOpCols, utils::words_to_bytes_le_vec};

pub const fn num_fp_cols_supervisor<P: FpOpField>() -> usize {
    std::mem::size_of::<FpOpCols<u8, P, SupervisorMode>>()
}

pub const fn num_fp_cols_user<P: FpOpField>() -> usize {
    std::mem::size_of::<FpOpCols<u8, P, UserMode>>()
}

pub struct FpOpChip<P, M: TrustMode> {
    _marker: PhantomData<(P, M)>,
}

/// A set of columns for the FpAdd operation.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct FpOpCols<T, P: FpOpField, M: TrustMode> {
    pub is_real: T,
    pub clk_high: T,
    pub clk_low: T,
    pub is_add: T,
    pub is_sub: T,
    pub is_mul: T,
    pub x_ptr: SyscallAddrOperation<T>,
    pub y_ptr: SyscallAddrOperation<T>,
    pub x_addrs: GenericArray<AddrAddOperation<T>, P::WordsFieldElement>,
    pub y_addrs: GenericArray<AddrAddOperation<T>, P::WordsFieldElement>,
    pub x_access: GenericArray<MemoryAccessColsU8<T>, P::WordsFieldElement>,
    pub y_access: GenericArray<MemoryAccessColsU8<T>, P::WordsFieldElement>,
    pub read_slice_page_prot_access: M::SliceProtCols<T>,
    pub write_slice_page_prot_access: M::SliceProtCols<T>,
    pub(crate) output: FieldOpCols<T, P>,
    pub(crate) output_range: FieldLtCols<T, P>,
}

impl<P: FpOpField, M: TrustMode> FpOpChip<P, M> {
    pub const fn new() -> Self {
        Self { _marker: PhantomData }
    }

    #[allow(clippy::too_many_arguments)]
    fn populate_field_ops<F: PrimeField32>(
        blu_events: &mut Vec<ByteLookupEvent>,
        cols: &mut FpOpCols<F, P, M>,
        p: BigUint,
        q: BigUint,
        op: FieldOperation,
    ) {
        let modulus_bytes = P::MODULUS;
        let modulus = BigUint::from_bytes_le(modulus_bytes);
        let output = cols.output.populate_with_modulus(blu_events, &p, &q, &modulus, op);
        cols.output_range.populate(blu_events, &output, &modulus);
    }
}

impl<F: PrimeField32, P: FpOpField, M: TrustMode> MachineAir<F> for FpOpChip<P, M> {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        match (P::FIELD_TYPE, M::IS_TRUSTED) {
            (FieldType::Bn254, true) => "Bn254FpOpAssign",
            (FieldType::Bn254, false) => "Bn254FpOpAssignUser",
            (FieldType::Bls12381, true) => "Bls12381FpOpAssign",
            (FieldType::Bls12381, false) => "Bls12381FpOpAssignUser",
        }
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return Some(0);
        }
        let nb_rows = match P::FIELD_TYPE {
            FieldType::Bn254 => input.get_precompile_events(SyscallCode::BN254_FP_ADD).len(),
            FieldType::Bls12381 => input.get_precompile_events(SyscallCode::BLS12381_FP_ADD).len(),
        };
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_multiple_of_32(nb_rows, size_log2);
        Some(padded_nb_rows)
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return;
        }

        let width = <FpOpChip<P, M> as BaseAir<F>>::width(self);
        let padded_nb_rows = <FpOpChip<P, M> as MachineAir<F>>::num_rows(self, input).unwrap();

        let events = match P::FIELD_TYPE {
            FieldType::Bn254 => input.get_precompile_events(SyscallCode::BN254_FP_ADD),
            FieldType::Bls12381 => input.get_precompile_events(SyscallCode::BLS12381_FP_ADD),
        };

        let num_event_rows = events.len();
        let mut new_byte_lookup_events = Vec::new();

        unsafe {
            let padding_start = num_event_rows * width;
            let padding_size = (padded_nb_rows - num_event_rows) * width;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe { core::slice::from_raw_parts_mut(buffer_ptr, num_event_rows * width) };

        values.chunks_exact_mut(width).enumerate().for_each(|(idx, row)| {
            let (_, event) = &events[idx];
            let event = match (P::FIELD_TYPE, event) {
                (FieldType::Bn254, PrecompileEvent::Bn254Fp(event)) => event,
                (FieldType::Bls12381, PrecompileEvent::Bls12381Fp(event)) => event,
                _ => unreachable!(),
            };

            let cols: &mut FpOpCols<F, P, M> = row.borrow_mut();

            let p = BigUint::from_bytes_le(&words_to_bytes_le_vec(&event.x));
            let q = BigUint::from_bytes_le(&words_to_bytes_le_vec(&event.y));

            cols.is_add = F::from_canonical_u8((event.op == FieldOperation::Add) as u8);
            cols.is_sub = F::from_canonical_u8((event.op == FieldOperation::Sub) as u8);
            cols.is_mul = F::from_canonical_u8((event.op == FieldOperation::Mul) as u8);
            cols.is_real = F::one();

            cols.clk_high = F::from_canonical_u32((event.clk >> 24) as u32);
            cols.clk_low = F::from_canonical_u32((event.clk & 0xFFFFFF) as u32);
            cols.x_ptr.populate(&mut new_byte_lookup_events, event.x_ptr, P::NB_LIMBS as u64);
            cols.y_ptr.populate(&mut new_byte_lookup_events, event.y_ptr, P::NB_LIMBS as u64);

            Self::populate_field_ops(&mut new_byte_lookup_events, cols, p, q, event.op);

            let mut is_not_trap = true;
            let mut trap_code = 0u8;

            if !M::IS_TRUSTED {
                let cols: &mut FpOpCols<F, P, UserMode> = row.borrow_mut();
                cols.read_slice_page_prot_access.populate(
                    &mut new_byte_lookup_events,
                    event.y_ptr,
                    event.y_ptr + 8 * (cols.y_addrs.len() - 1) as u64,
                    event.clk,
                    PROT_READ,
                    &event.page_prot_records.read_page_prot_records,
                    &mut is_not_trap,
                    &mut trap_code,
                );

                cols.write_slice_page_prot_access.populate(
                    &mut new_byte_lookup_events,
                    event.x_ptr,
                    event.x_ptr + 8 * (cols.x_addrs.len() - 1) as u64,
                    event.clk + 1,
                    PROT_READ | PROT_WRITE,
                    &event.page_prot_records.write_page_prot_records,
                    &mut is_not_trap,
                    &mut trap_code,
                );
            }

            // Populate the memory access columns.
            let cols: &mut FpOpCols<F, P, M> = row.borrow_mut();
            for i in 0..cols.y_addrs.len() {
                cols.y_addrs[i].populate(&mut new_byte_lookup_events, event.y_ptr, i as u64 * 8);
            }
            for i in 0..cols.x_addrs.len() {
                cols.x_addrs[i].populate(&mut new_byte_lookup_events, event.x_ptr, i as u64 * 8);
            }
            if is_not_trap {
                for i in 0..cols.y_access.len() {
                    let record = MemoryRecordEnum::Read(event.y_memory_records[i]);
                    cols.y_access[i].populate(record, &mut new_byte_lookup_events);
                }
                for i in 0..cols.x_access.len() {
                    let record = MemoryRecordEnum::Write(event.x_memory_records[i]);
                    cols.x_access[i].populate(record, &mut new_byte_lookup_events);
                }
            } else {
                for i in 0..cols.y_access.len() {
                    cols.y_access[i] = MemoryAccessColsU8::default();
                }
                for i in 0..cols.x_access.len() {
                    cols.x_access[i] = MemoryAccessColsU8::default();
                }
            }
        });

        output.add_byte_lookup_events(new_byte_lookup_events);

        for idx in num_event_rows..padded_nb_rows {
            let row_start = idx * width;
            let row = unsafe {
                core::slice::from_raw_parts_mut(buffer[row_start..].as_mut_ptr() as *mut F, width)
            };

            let cols: &mut FpOpCols<F, P, M> = row.borrow_mut();
            let zero = BigUint::zero();
            cols.is_add = F::from_canonical_u8(1);
            Self::populate_field_ops(&mut vec![], cols, zero.clone(), zero, FieldOperation::Add);
        }
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if M::IS_TRUSTED == shard.program.enable_untrusted_programs {
            return false;
        }

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

impl<F, P: FpOpField, M: TrustMode> BaseAir<F> for FpOpChip<P, M> {
    fn width(&self) -> usize {
        if M::IS_TRUSTED {
            num_fp_cols_supervisor::<P>()
        } else {
            num_fp_cols_user::<P>()
        }
    }
}

impl<AB, P: FpOpField, M: TrustMode> Air<AB> for FpOpChip<P, M>
where
    AB: SP1CoreAirBuilder,
    Limbs<AB::Var, <P as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &FpOpCols<AB::Var, P, M> = (*local).borrow();

        // Check that operations flags are boolean.
        builder.assert_bool(local.is_add);
        builder.assert_bool(local.is_sub);
        builder.assert_bool(local.is_mul);
        builder.assert_bool(local.is_real);

        // Check that only one of them is set.
        builder.assert_eq(local.is_add + local.is_sub + local.is_mul, AB::Expr::one());

        let mut is_not_trap = local.is_real.into();
        let mut trap_code = AB::Expr::zero();

        if !M::IS_TRUSTED {
            let local = main.row_slice(0);
            let local: &FpOpCols<AB::Var, P, UserMode> = (*local).borrow();

            #[cfg(not(feature = "mprotect"))]
            builder.assert_zero(local.is_real);

            AddressSlicePageProtOperation::<AB::F>::eval(
                builder,
                local.clk_high.into(),
                local.clk_low.into(),
                &local.y_ptr.addr.map(Into::into),
                &local.y_addrs[local.y_addrs.len() - 1].value.map(Into::into),
                PROT_READ,
                &local.read_slice_page_prot_access,
                &mut is_not_trap,
                &mut trap_code,
            );

            AddressSlicePageProtOperation::<AB::F>::eval(
                builder,
                local.clk_high.into(),
                local.clk_low.into() + AB::Expr::one(),
                &local.x_ptr.addr.map(Into::into),
                &local.x_addrs[local.x_addrs.len() - 1].value.map(Into::into),
                PROT_READ | PROT_WRITE,
                &local.write_slice_page_prot_access,
                &mut is_not_trap,
                &mut trap_code,
            );
        }

        let p_limbs = builder.generate_limbs(&local.x_access, is_not_trap.clone());
        let p: Limbs<AB::Expr, <P as NumLimbs>::Limbs> =
            Limbs(p_limbs.try_into().expect("failed to convert limbs"));
        let q_limbs = builder.generate_limbs(&local.y_access, is_not_trap.clone());
        let q: Limbs<AB::Expr, <P as NumLimbs>::Limbs> =
            Limbs(q_limbs.try_into().expect("failed to convert limbs"));

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

        local.output_range.eval(builder, &local.output.result, &p_modulus, local.is_real);

        let result_words = limbs_to_words::<AB>(local.output.result.0.to_vec());

        let x_ptr = SyscallAddrOperation::<AB::F>::eval(
            builder,
            P::NB_LIMBS as u32,
            local.x_ptr,
            local.is_real.into(),
        );
        let y_ptr = SyscallAddrOperation::<AB::F>::eval(
            builder,
            P::NB_LIMBS as u32,
            local.y_ptr,
            local.is_real.into(),
        );

        // x_addrs[i] = x_ptr + 8 * i
        for i in 0..local.x_addrs.len() {
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([x_ptr[0].into(), x_ptr[1].into(), x_ptr[2].into(), AB::Expr::zero()]),
                Word::from(8 * i as u64),
                local.x_addrs[i],
                local.is_real.into(),
            );
        }

        // y_addrs[i] = y_ptr + 8 * i
        for i in 0..local.y_addrs.len() {
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([y_ptr[0].into(), y_ptr[1].into(), y_ptr[2].into(), AB::Expr::zero()]),
                Word::from(8 * i as u64),
                local.y_addrs[i],
                local.is_real.into(),
            );
        }

        builder.eval_memory_access_slice_read(
            local.clk_high,
            local.clk_low,
            &local.y_addrs.iter().map(|addr| addr.value.map(Into::into)).collect::<Vec<_>>(),
            &local.y_access.iter().map(|access| access.memory_access).collect::<Vec<_>>(),
            is_not_trap.clone(),
        );

        // We read p at +1 since p, q could be the same.
        builder.eval_memory_access_slice_write(
            local.clk_high,
            local.clk_low + AB::Expr::one(),
            &local.x_addrs.iter().map(|addr| addr.value.map(Into::into)).collect::<Vec<_>>(),
            &local.x_access.iter().map(|access| access.memory_access).collect::<Vec<_>>(),
            result_words,
            is_not_trap.clone(),
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
            local.clk_high,
            local.clk_low,
            syscall_id_felt,
            trap_code.clone(),
            x_ptr.map(Into::into),
            y_ptr.map(Into::into),
            local.is_real,
            InteractionScope::Local,
        );

        #[cfg(feature = "mprotect")]
        builder.assert_eq(
            builder.extract_public_values().is_untrusted_programs_enabled,
            AB::Expr::from_bool(!M::IS_TRUSTED),
        );
    }
}
