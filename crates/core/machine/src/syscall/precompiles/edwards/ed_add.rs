use core::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, MaybeUninit},
};
use std::{fmt::Debug, marker::PhantomData};

use crate::{
    air::SP1CoreAirBuilder,
    memory::MemoryAccessColsU8,
    operations::{AddrAddOperation, AddressSlicePageProtOperation, SyscallAddrOperation},
    utils::{limbs_to_words, next_multiple_of_32},
    SupervisorMode, TrustMode, UserMode,
};
use hashbrown::HashMap;
use itertools::Itertools;
use num::{BigUint, Zero};
use slop_air::{Air, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use slop_maybe_rayon::prelude::{
    IndexedParallelIterator, ParallelIterator, ParallelSlice, ParallelSliceMut,
};
use sp1_core_executor::{
    events::{
        ByteLookupEvent, ByteRecord, EllipticCurveAddEvent, FieldOperation, MemoryRecordEnum,
        PrecompileEvent,
    },
    ExecutionRecord, Program, SyscallCode,
};
use sp1_curves::{
    edwards::{ed25519::Ed25519BaseField, EdwardsParameters, WORDS_CURVE_POINT},
    params::{FieldParameters, Limbs, NumLimbs},
    AffinePoint, EllipticCurve,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{
    air::{InteractionScope, MachineAir},
    Word,
};
use sp1_primitives::consts::{PROT_READ, PROT_WRITE};

use crate::operations::field::{
    field_den::FieldDenCols, field_inner_product::FieldInnerProductCols, field_op::FieldOpCols,
    range::FieldLtCols,
};

pub const NUM_ED_ADD_COLS_SUPERVISOR: usize = size_of::<EdAddAssignCols<u8, SupervisorMode>>();
pub const NUM_ED_ADD_COLS_USER: usize = size_of::<EdAddAssignCols<u8, UserMode>>();

/// A set of columns to compute `EdAdd` where a, b are field elements.
/// Right now the number of limbs is assumed to be a constant, although this could be macro-ed
/// or made generic in the future.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct EdAddAssignCols<T, M: TrustMode> {
    pub is_real: T,
    pub clk_high: T,
    pub clk_low: T,
    pub p_ptr: SyscallAddrOperation<T>,
    pub q_ptr: SyscallAddrOperation<T>,
    pub p_addrs_add: [AddrAddOperation<T>; WORDS_CURVE_POINT],
    pub q_addrs_add: [AddrAddOperation<T>; WORDS_CURVE_POINT],
    pub p_access: [MemoryAccessColsU8<T>; WORDS_CURVE_POINT],
    pub q_access: [MemoryAccessColsU8<T>; WORDS_CURVE_POINT],
    pub(crate) x3_numerator: FieldInnerProductCols<T, Ed25519BaseField>,
    pub(crate) y3_numerator: FieldInnerProductCols<T, Ed25519BaseField>,
    pub(crate) x1_mul_y1: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) x2_mul_y2: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) f: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) d_mul_f: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) x3_ins: FieldDenCols<T, Ed25519BaseField>,
    pub(crate) y3_ins: FieldDenCols<T, Ed25519BaseField>,
    pub(crate) x3_range: FieldLtCols<T, Ed25519BaseField>,
    pub(crate) y3_range: FieldLtCols<T, Ed25519BaseField>,
    pub read_slice_page_prot_access: M::SliceProtCols<T>,
    pub write_slice_page_prot_access: M::SliceProtCols<T>,
}

#[derive(Default)]
pub struct EdAddAssignChip<E, M: TrustMode> {
    _marker: PhantomData<(E, M)>,
}

impl<E: EllipticCurve + EdwardsParameters, M: TrustMode> EdAddAssignChip<E, M> {
    pub const fn new() -> Self {
        Self { _marker: PhantomData }
    }

    #[allow(clippy::too_many_arguments)]
    fn populate_field_ops<F: PrimeField32>(
        record: &mut impl ByteRecord,
        cols: &mut EdAddAssignCols<F, M>,
        p_x: BigUint,
        p_y: BigUint,
        q_x: BigUint,
        q_y: BigUint,
    ) {
        let x3_numerator = cols.x3_numerator.populate(
            record,
            &[p_x.clone(), q_x.clone()],
            &[q_y.clone(), p_y.clone()],
        );
        let y3_numerator = cols.y3_numerator.populate(
            record,
            &[p_y.clone(), p_x.clone()],
            &[q_y.clone(), q_x.clone()],
        );
        let x1_mul_y1 = cols.x1_mul_y1.populate(record, &p_x, &p_y, FieldOperation::Mul);
        let x2_mul_y2 = cols.x2_mul_y2.populate(record, &q_x, &q_y, FieldOperation::Mul);
        let f = cols.f.populate(record, &x1_mul_y1, &x2_mul_y2, FieldOperation::Mul);

        let d = E::d_biguint();
        let d_mul_f = cols.d_mul_f.populate(record, &f, &d, FieldOperation::Mul);

        let x3 = cols.x3_ins.populate(record, &x3_numerator, &d_mul_f, true);
        let y3 = cols.y3_ins.populate(record, &y3_numerator, &d_mul_f, false);

        cols.x3_range.populate(record, &x3, &Ed25519BaseField::modulus());
        cols.y3_range.populate(record, &y3, &Ed25519BaseField::modulus());
    }
}

impl<F: PrimeField32, E: EllipticCurve + EdwardsParameters, M: TrustMode> MachineAir<F>
    for EdAddAssignChip<E, M>
{
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        if M::IS_TRUSTED {
            "EdAddAssign"
        } else {
            "EdAddAssignUser"
        }
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return Some(0);
        }
        let nb_rows = input.get_precompile_events(SyscallCode::ED_ADD).len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_multiple_of_32(nb_rows, size_log2);
        Some(padded_nb_rows)
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return;
        }

        let width = <EdAddAssignChip<E, M> as BaseAir<F>>::width(self);
        let padded_nb_rows =
            <EdAddAssignChip<E, M> as MachineAir<F>>::num_rows(self, input).unwrap();
        let events = input.get_precompile_events(SyscallCode::ED_ADD);
        let num_event_rows = events.len();

        unsafe {
            let padding_start = num_event_rows * width;
            let padding_size = (padded_nb_rows - num_event_rows) * width;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe { core::slice::from_raw_parts_mut(buffer_ptr, num_event_rows * width) };

        values.par_chunks_mut(width).enumerate().for_each(|(idx, row)| {
            if idx < events.len() {
                let (_, event) = &events[idx];
                let event = if let PrecompileEvent::EdAdd(event) = event {
                    event
                } else {
                    unreachable!();
                };
                let cols: &mut EdAddAssignCols<F, M> = row.borrow_mut();
                let mut blu = Vec::new();
                self.event_to_row(event, cols, &mut blu);
            }
        });

        for idx in num_event_rows..padded_nb_rows {
            let row_start = idx * width;
            let row = unsafe {
                core::slice::from_raw_parts_mut(buffer[row_start..].as_mut_ptr() as *mut F, width)
            };
            let cols: &mut EdAddAssignCols<F, M> = row.borrow_mut();
            let zero = BigUint::zero();
            Self::populate_field_ops(
                &mut vec![],
                cols,
                zero.clone(),
                zero.clone(),
                zero.clone(),
                zero,
            );
        }
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return;
        }

        let width = <EdAddAssignChip<E, M> as BaseAir<F>>::width(self);
        let events = input.get_precompile_events(SyscallCode::ED_ADD);
        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        let blu_batches = events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|(_, event)| {
                    let event = if let PrecompileEvent::EdAdd(event) = event {
                        event
                    } else {
                        unreachable!();
                    };

                    let mut row = vec![F::zero(); width];
                    let cols: &mut EdAddAssignCols<F, M> = row.as_mut_slice().borrow_mut();
                    self.event_to_row(event, cols, &mut blu);
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_batches.iter().collect_vec());
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::ED_ADD).is_empty()
                && (M::IS_TRUSTED != shard.program.enable_untrusted_programs)
        }
    }
}

impl<E: EllipticCurve + EdwardsParameters, M: TrustMode> EdAddAssignChip<E, M> {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &EllipticCurveAddEvent,
        cols: &mut EdAddAssignCols<F, M>,
        blu: &mut impl ByteRecord,
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

        cols.p_ptr.populate(blu, event.p_ptr, 64);
        cols.q_ptr.populate(blu, event.q_ptr, 64);

        Self::populate_field_ops(blu, cols, p_x, p_y, q_x, q_y);

        let mut is_not_trap = true;
        let mut trap_code = 0;

        if !M::IS_TRUSTED {
            let cols: &mut EdAddAssignCols<F, UserMode> =
                unsafe { &mut *(cols as *mut _ as *mut _) };
            cols.read_slice_page_prot_access.populate(
                blu,
                event.q_ptr,
                event.q_ptr + 8 * (WORDS_CURVE_POINT - 1) as u64,
                event.clk,
                PROT_READ,
                &event.page_prot_records.read_page_prot_records,
                &mut is_not_trap,
                &mut trap_code,
            );

            cols.write_slice_page_prot_access.populate(
                blu,
                event.p_ptr,
                event.p_ptr + 8 * (WORDS_CURVE_POINT - 1) as u64,
                event.clk + 1,
                PROT_READ | PROT_WRITE,
                &event.page_prot_records.write_page_prot_records,
                &mut is_not_trap,
                &mut trap_code,
            );
        }

        // Populate the memory access columns.
        for i in 0..WORDS_CURVE_POINT {
            cols.q_addrs_add[i].populate(blu, event.q_ptr, i as u64 * 8);
            cols.p_addrs_add[i].populate(blu, event.p_ptr, i as u64 * 8);
            if is_not_trap {
                let q_record = MemoryRecordEnum::Read(event.q_memory_records[i]);
                cols.q_access[i].populate(q_record, blu);
                let p_record = MemoryRecordEnum::Write(event.p_memory_records[i]);
                cols.p_access[i].populate(p_record, blu);
            } else {
                cols.q_access[i] = MemoryAccessColsU8::default();
                cols.p_access[i] = MemoryAccessColsU8::default();
            }
        }
    }
}

impl<F, E: EllipticCurve + EdwardsParameters, M: TrustMode> BaseAir<F> for EdAddAssignChip<E, M> {
    fn width(&self) -> usize {
        if M::IS_TRUSTED {
            NUM_ED_ADD_COLS_SUPERVISOR
        } else {
            NUM_ED_ADD_COLS_USER
        }
    }
}

impl<AB, E: EllipticCurve + EdwardsParameters, M: TrustMode> Air<AB> for EdAddAssignChip<E, M>
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &EdAddAssignCols<AB::Var, M> = (*local).borrow();

        let mut is_not_trap = local.is_real.into();
        let mut trap_code = AB::Expr::zero();

        if !M::IS_TRUSTED {
            let local = main.row_slice(0);
            let local: &EdAddAssignCols<AB::Var, UserMode> = (*local).borrow();

            #[cfg(not(feature = "mprotect"))]
            builder.assert_zero(local.is_real);

            AddressSlicePageProtOperation::<AB::F>::eval(
                builder,
                local.clk_high.into(),
                local.clk_low.into(),
                &local.q_ptr.addr.map(Into::into),
                &local.q_addrs_add[WORDS_CURVE_POINT - 1].value.map(Into::into),
                PROT_READ,
                &local.read_slice_page_prot_access,
                &mut is_not_trap,
                &mut trap_code,
            );

            AddressSlicePageProtOperation::<AB::F>::eval(
                builder,
                local.clk_high.into(),
                local.clk_low.into() + AB::Expr::one(),
                &local.p_ptr.addr.map(Into::into),
                &local.p_addrs_add[WORDS_CURVE_POINT - 1].value.map(Into::into),
                PROT_READ | PROT_WRITE,
                &local.write_slice_page_prot_access,
                &mut is_not_trap,
                &mut trap_code,
            );
        }

        let x1_limbs = builder.generate_limbs(&local.p_access[0..4], is_not_trap.clone());
        let x1: Limbs<AB::Expr, <Ed25519BaseField as NumLimbs>::Limbs> =
            Limbs(x1_limbs.try_into().expect("failed to convert limbs"));
        let x2_limbs = builder.generate_limbs(&local.q_access[0..4], is_not_trap.clone());
        let x2: Limbs<AB::Expr, <Ed25519BaseField as NumLimbs>::Limbs> =
            Limbs(x2_limbs.try_into().expect("failed to convert limbs"));
        let y1_limbs = builder.generate_limbs(&local.p_access[4..8], is_not_trap.clone());
        let y1: Limbs<AB::Expr, <Ed25519BaseField as NumLimbs>::Limbs> =
            Limbs(y1_limbs.try_into().expect("failed to convert limbs"));
        let y2_limbs = builder.generate_limbs(&local.q_access[4..8], is_not_trap.clone());
        let y2: Limbs<AB::Expr, <Ed25519BaseField as NumLimbs>::Limbs> =
            Limbs(y2_limbs.try_into().expect("failed to convert limbs"));

        // x3_numerator = x1 * y2 + x2 * y1.
        local.x3_numerator.eval(
            builder,
            &[x1.clone(), x2.clone()],
            &[y2.clone(), y1.clone()],
            local.is_real,
        );

        // y3_numerator = y1 * y2 + x1 * x2.
        local.y3_numerator.eval(
            builder,
            &[y1.clone(), x1.clone()],
            &[y2.clone(), x2.clone()],
            local.is_real,
        );

        // f = x1 * x2 * y1 * y2.
        local.x1_mul_y1.eval(builder, &x1.clone(), &y1.clone(), FieldOperation::Mul, local.is_real);
        local.x2_mul_y2.eval(builder, &x2.clone(), &y2.clone(), FieldOperation::Mul, local.is_real);

        let x1_mul_y1 = local.x1_mul_y1.result;
        let x2_mul_y2 = local.x2_mul_y2.result;
        local.f.eval(builder, &x1_mul_y1, &x2_mul_y2, FieldOperation::Mul, local.is_real);

        // d * f.
        let f = local.f.result;
        let d_biguint = E::d_biguint();
        let d_const = E::BaseField::to_limbs_field::<AB::Expr, _>(&d_biguint);
        local.d_mul_f.eval(builder, &f, &d_const, FieldOperation::Mul, local.is_real);

        let d_mul_f = local.d_mul_f.result;

        let modulus =
            Ed25519BaseField::to_limbs_field::<AB::Expr, AB::F>(&Ed25519BaseField::modulus());

        // x3 = x3_numerator / (1 + d * f).
        local.x3_ins.eval(builder, &local.x3_numerator.result, &d_mul_f, true, local.is_real);
        local.x3_range.eval(builder, &local.x3_ins.result, &modulus, local.is_real);

        // y3 = y3_numerator / (1 - d * f).
        local.y3_ins.eval(builder, &local.y3_numerator.result, &d_mul_f, false, local.is_real);
        local.y3_range.eval(builder, &local.y3_ins.result, &modulus, local.is_real);

        let x_result_words = limbs_to_words::<AB>(local.x3_ins.result.0.to_vec());
        let y_result_words = limbs_to_words::<AB>(local.y3_ins.result.0.to_vec());

        let result_words = x_result_words.into_iter().chain(y_result_words).collect_vec();

        let p_ptr =
            SyscallAddrOperation::<AB::F>::eval(builder, 64, local.p_ptr, local.is_real.into());

        let q_ptr =
            SyscallAddrOperation::<AB::F>::eval(builder, 64, local.q_ptr, local.is_real.into());

        // q_addrs_add[i] = q_ptr + 8 * i.
        for i in 0..WORDS_CURVE_POINT {
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([q_ptr[0].into(), q_ptr[1].into(), q_ptr[2].into(), AB::Expr::zero()]),
                Word::from(8 * i as u64),
                local.q_addrs_add[i],
                local.is_real.into(),
            );
        }

        // p_addrs_add[i] = p_ptr + 8 * i.
        for i in 0..WORDS_CURVE_POINT {
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([p_ptr[0].into(), p_ptr[1].into(), p_ptr[2].into(), AB::Expr::zero()]),
                Word::from(8 * i as u64),
                local.p_addrs_add[i],
                local.is_real.into(),
            );
        }

        builder.eval_memory_access_slice_read(
            local.clk_high,
            local.clk_low,
            &local.q_addrs_add.map(|addr| addr.value.map(Into::into)),
            &local.q_access.iter().map(|access| access.memory_access).collect_vec(),
            is_not_trap.clone(),
        );

        builder.eval_memory_access_slice_write(
            local.clk_high,
            local.clk_low + AB::Expr::one(),
            &local.p_addrs_add.map(|addr| addr.value.map(Into::into)),
            &local.p_access.iter().map(|access| access.memory_access).collect_vec(),
            result_words,
            is_not_trap.clone(),
        );

        builder.receive_syscall(
            local.clk_high,
            local.clk_low,
            AB::F::from_canonical_u32(SyscallCode::ED_ADD.syscall_id()),
            trap_code.clone(),
            p_ptr.map(Into::into),
            q_ptr.map(Into::into),
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use sp1_core_executor::Program;
    use test_artifacts::{ED25519_ELF, ED_ADD_ELF};

    use crate::{io::SP1Stdin, utils};

    #[tokio::test(flavor = "multi_thread")]
    async fn test_ed_add_simple() {
        utils::setup_logger();
        let program = Program::from(&ED_ADD_ELF).unwrap();
        let stdin = SP1Stdin::new();
        utils::run_test(Arc::new(program), stdin).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_ed25519_program() {
        utils::setup_logger();
        let program = Program::from(&ED25519_ELF).unwrap();
        let stdin = SP1Stdin::new();
        utils::run_test(Arc::new(program), stdin).await.unwrap();
    }
}
