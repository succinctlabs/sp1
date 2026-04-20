use crate::{
    air::SP1CoreAirBuilder,
    memory::{MemoryAccessCols, MemoryAccessColsU8},
    operations::{AddrAddOperation, AddressSlicePageProtOperation, SyscallAddrOperation},
    utils::{limbs_to_words, next_multiple_of_32},
    SupervisorMode, TrustMode, UserMode,
};
use core::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, MaybeUninit},
};
use generic_array::GenericArray;
use itertools::Itertools;
use num::{BigUint, One, Zero};
use slop_air::{Air, AirBuilder, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use sp1_core_executor::{
    events::{
        ByteLookupEvent, ByteRecord, EdDecompressEvent, FieldOperation, MemoryRecordEnum,
        PrecompileEvent,
    },
    ExecutionRecord, Program, SyscallCode,
};
use sp1_curves::{
    edwards::{
        ed25519::{ed25519_sqrt, Ed25519BaseField},
        EdwardsParameters, WordsFieldElement, WORDS_FIELD_ELEMENT,
    },
    params::{FieldParameters, Limbs},
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{
    air::{BaseAirBuilder, InteractionScope, MachineAir},
    Word,
};
use sp1_primitives::consts::{PROT_READ, PROT_WRITE};
use std::marker::PhantomData;
use typenum::U32;

use crate::operations::field::{
    field_op::FieldOpCols, field_sqrt::FieldSqrtCols, range::FieldLtCols,
};

pub const NUM_ED_DECOMPRESS_COLS_SUPERVISOR: usize =
    size_of::<EdDecompressCols<u8, SupervisorMode>>();
pub const NUM_ED_DECOMPRESS_COLS_USER: usize = size_of::<EdDecompressCols<u8, UserMode>>();

/// The number of columns in the EdDecompressCols (supervisor mode).
pub const fn num_ed_decompress_cols_supervisor() -> usize {
    size_of::<EdDecompressCols<u8, SupervisorMode>>()
}

/// The number of columns in the EdDecompressCols (user mode).
pub const fn num_ed_decompress_cols_user() -> usize {
    size_of::<EdDecompressCols<u8, UserMode>>()
}

/// A set of columns to compute `EdDecompress` given a pointer to a 16 word slice formatted as such:
/// The 31st byte of the slice is the sign bit. The second half of the slice is the 255-bit
/// compressed Y (without sign bit).
///
/// After `EdDecompress`, the first 32 bytes of the slice are overwritten with the decompressed X.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct EdDecompressCols<T, M: TrustMode> {
    pub is_real: T,
    pub clk_high: T,
    pub clk_low: T,
    pub ptr: SyscallAddrOperation<T>,
    pub read_ptrs: [AddrAddOperation<T>; WORDS_FIELD_ELEMENT],
    pub addrs: [AddrAddOperation<T>; WORDS_FIELD_ELEMENT],
    pub sign: T,
    pub x_access: GenericArray<MemoryAccessCols<T>, WordsFieldElement>,
    pub x_value: GenericArray<Word<T>, WordsFieldElement>,
    pub y_access: GenericArray<MemoryAccessColsU8<T>, WordsFieldElement>,
    pub read_slice_page_prot_access: M::SliceProtCols<T>,
    pub write_slice_page_prot_access: M::SliceProtCols<T>,
    pub(crate) neg_x_range: FieldLtCols<T, Ed25519BaseField>,
    pub(crate) y_range: FieldLtCols<T, Ed25519BaseField>,
    pub(crate) yy: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) u: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) dyy: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) v: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) u_div_v: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) x: FieldSqrtCols<T, Ed25519BaseField>,
    pub(crate) neg_x: FieldOpCols<T, Ed25519BaseField>,
}

impl<F: PrimeField32, M: TrustMode> EdDecompressCols<F, M> {
    pub fn populate<P: FieldParameters, E: EdwardsParameters>(
        &mut self,
        event: EdDecompressEvent,
        record: &mut ExecutionRecord,
        is_not_trap: bool,
    ) {
        let mut new_byte_lookup_events = Vec::new();
        self.is_real = F::from_bool(true);
        self.clk_high = F::from_canonical_u32((event.clk >> 24) as u32);
        self.clk_low = F::from_canonical_u32((event.clk & 0xFFFFFF) as u32);
        self.ptr.populate(record, event.ptr, 64);

        // WORDS_FIELD_ELEMENT * 8 = 32
        let read_ptr = event.ptr + 32;

        self.sign = F::from_bool(event.sign);
        for i in 0..WORDS_FIELD_ELEMENT {
            let x_record = MemoryRecordEnum::Write(event.x_memory_records[i]);
            let y_record = MemoryRecordEnum::Read(event.y_memory_records[i]);
            let current_x_record = x_record.current_record();
            self.x_value[i] = Word::from(current_x_record.value);
            self.addrs[i].populate(record, event.ptr, i as u64 * 8);
            self.read_ptrs[i].populate(record, read_ptr, i as u64 * 8);
            if is_not_trap {
                self.x_access[i].populate(x_record, &mut new_byte_lookup_events);
                self.y_access[i].populate(y_record, &mut new_byte_lookup_events);
            } else {
                self.x_access[i] = MemoryAccessCols::default();
                self.y_access[i] = MemoryAccessColsU8::default();
            }
        }

        let y = &BigUint::from_bytes_le(&event.y_bytes);
        self.populate_field_ops::<E>(&mut new_byte_lookup_events, y);

        record.add_byte_lookup_events(new_byte_lookup_events);
    }

    pub fn populate_page_prot(
        cols: &mut EdDecompressCols<F, UserMode>,
        event: &EdDecompressEvent,
        new_byte_lookup_events: &mut Vec<ByteLookupEvent>,
        is_not_trap: &mut bool,
        trap_code: &mut u8,
    ) {
        let read_ptr = event.ptr + 32;
        cols.read_slice_page_prot_access.populate(
            new_byte_lookup_events,
            read_ptr,
            read_ptr + 8 * (WORDS_FIELD_ELEMENT - 1) as u64,
            event.clk,
            PROT_READ,
            &event.page_prot_records.read_page_prot_records,
            is_not_trap,
            trap_code,
        );

        cols.write_slice_page_prot_access.populate(
            new_byte_lookup_events,
            event.ptr,
            event.ptr + 8 * (WORDS_FIELD_ELEMENT - 1) as u64,
            event.clk + 1,
            PROT_WRITE,
            &event.page_prot_records.write_page_prot_records,
            is_not_trap,
            trap_code,
        );
    }

    fn populate_field_ops<E: EdwardsParameters>(
        &mut self,
        blu_events: &mut Vec<ByteLookupEvent>,
        y: &BigUint,
    ) {
        let one = BigUint::one();
        self.y_range.populate(blu_events, y, &Ed25519BaseField::modulus());
        let yy = self.yy.populate(blu_events, y, y, FieldOperation::Mul);
        let u = self.u.populate(blu_events, &yy, &one, FieldOperation::Sub);
        let dyy = self.dyy.populate(blu_events, &E::d_biguint(), &yy, FieldOperation::Mul);
        let v = self.v.populate(blu_events, &one, &dyy, FieldOperation::Add);
        let u_div_v = self.u_div_v.populate(blu_events, &u, &v, FieldOperation::Div);

        let x = self.x.populate(blu_events, &u_div_v, |v| {
            ed25519_sqrt(v).expect("curve25519 expected field element to be a square")
        });
        let neg_x = self.neg_x.populate(blu_events, &BigUint::zero(), &x, FieldOperation::Sub);
        self.neg_x_range.populate(blu_events, &neg_x, &Ed25519BaseField::modulus());
    }
}

impl<V: Copy, M: TrustMode> EdDecompressCols<V, M> {
    pub fn eval<AB: SP1CoreAirBuilder<Var = V>, P: FieldParameters, E: EdwardsParameters>(
        &self,
        builder: &mut AB,
        is_not_trap: AB::Expr,
        trap_code: AB::Expr,
    ) where
        V: Into<AB::Expr>,
    {
        builder.assert_bool(self.sign);
        builder.assert_bool(self.is_real);

        let y_limbs = builder.generate_limbs(&self.y_access, is_not_trap.clone());
        let y: Limbs<AB::Expr, U32> = Limbs(y_limbs.try_into().expect("failed to convert limbs"));
        let max_num_limbs =
            Ed25519BaseField::to_limbs_field::<AB::Expr, AB::F>(&Ed25519BaseField::modulus());
        self.y_range.eval(builder, &y, &max_num_limbs, self.is_real);
        self.yy.eval(builder, &y, &y, FieldOperation::Mul, self.is_real);
        self.u.eval(
            builder,
            &self.yy.result,
            &[AB::Expr::one()].iter(),
            FieldOperation::Sub,
            self.is_real,
        );
        let d_biguint = E::d_biguint();
        let d_const = E::BaseField::to_limbs_field::<AB::F, _>(&d_biguint);
        self.dyy.eval(builder, &d_const, &self.yy.result, FieldOperation::Mul, self.is_real);
        self.v.eval(
            builder,
            &[AB::Expr::one()].iter(),
            &self.dyy.result,
            FieldOperation::Add,
            self.is_real,
        );
        self.u_div_v.eval(
            builder,
            &self.u.result,
            &self.v.result,
            FieldOperation::Div,
            self.is_real,
        );

        // Constrain that `x` is a square root. Note that `x.multiplication.result` is constrained
        // to be canonical here.
        self.x.eval(builder, &self.u_div_v.result, AB::F::zero(), self.is_real);
        self.neg_x.eval(
            builder,
            &[AB::Expr::zero()].iter(),
            &self.x.multiplication.result,
            FieldOperation::Sub,
            self.is_real,
        );
        // Constrain that `neg_x.result` is also canonical.
        self.neg_x_range.eval(builder, &self.neg_x.result, &max_num_limbs, self.is_real);

        let ptr = SyscallAddrOperation::<AB::F>::eval(builder, 64, self.ptr, self.is_real.into());

        // addrs[i] = ptr + 8 * i.
        for i in 0..WORDS_FIELD_ELEMENT {
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([ptr[0].into(), ptr[1].into(), ptr[2].into(), AB::Expr::zero()]),
                Word::from(8 * i as u64),
                self.addrs[i],
                self.is_real.into(),
            );
        }

        // read_ptrs[i] = ptr + 8 * i + 32.
        for i in 0..WORDS_FIELD_ELEMENT {
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([ptr[0].into(), ptr[1].into(), ptr[2].into(), AB::Expr::zero()]),
                Word::from(8 * i as u64 + 32),
                self.read_ptrs[i],
                self.is_real.into(),
            );
        }

        builder.eval_memory_access_slice_read(
            self.clk_high,
            self.clk_low,
            &self.read_ptrs.map(|ptr| ptr.value.map(Into::into)),
            &self.y_access.iter().map(|access| access.memory_access).collect_vec(),
            is_not_trap.clone(),
        );

        builder.eval_memory_access_slice_write(
            self.clk_high,
            self.clk_low.into() + AB::Expr::one(),
            &self.addrs.map(|addr| addr.value.map(Into::into)),
            &self.x_access,
            self.x_value.to_vec(),
            is_not_trap.clone(),
        );

        // Constrain that x_value is correct.
        // Since the result is either `neg_x.result` or `x.multiplication.result`, the written value
        // is canonical.
        let neg_x_words = limbs_to_words::<AB>(self.neg_x.result.0.to_vec());
        let mul_x_words = limbs_to_words::<AB>(self.x.multiplication.result.0.to_vec());
        let x_value_words = self.x_value.to_vec().iter().map(|w| w.map(|x| x.into())).collect_vec();
        for (neg_x_word, x_value_word) in neg_x_words.iter().zip(x_value_words.iter()) {
            builder
                .when(self.is_real)
                .when(self.sign)
                .assert_all_eq(neg_x_word.clone(), x_value_word.clone());
        }
        for (mul_x_word, x_value_word) in mul_x_words.iter().zip(x_value_words.iter()) {
            builder
                .when(self.is_real)
                .when_not(self.sign)
                .assert_all_eq(mul_x_word.clone(), x_value_word.clone());
        }

        builder.receive_syscall(
            self.clk_high,
            self.clk_low,
            AB::F::from_canonical_u32(SyscallCode::ED_DECOMPRESS.syscall_id()),
            trap_code.clone(),
            ptr.map(Into::into),
            [self.sign.into(), AB::Expr::zero(), AB::Expr::zero()],
            self.is_real,
            InteractionScope::Local,
        );
    }
}

impl<V: Copy> EdDecompressCols<V, UserMode> {
    pub fn eval_page_prot<AB: SP1CoreAirBuilder<Var = V>, E: EdwardsParameters>(
        &self,
        builder: &mut AB,
    ) -> (AB::Expr, AB::Expr)
    where
        V: Into<AB::Expr>,
    {
        let mut is_not_trap = self.is_real.into();
        let mut trap_code = AB::Expr::zero();

        AddressSlicePageProtOperation::<AB::F>::eval(
            builder,
            self.clk_high.into(),
            self.clk_low.into(),
            &self.read_ptrs[0].value.map(Into::into),
            &self.read_ptrs[WORDS_FIELD_ELEMENT - 1].value.map(Into::into),
            PROT_READ,
            &self.read_slice_page_prot_access,
            &mut is_not_trap,
            &mut trap_code,
        );

        AddressSlicePageProtOperation::<AB::F>::eval(
            builder,
            self.clk_high.into(),
            self.clk_low.into() + AB::Expr::one(),
            &self.addrs[0].value.map(Into::into),
            &self.addrs[WORDS_FIELD_ELEMENT - 1].value.map(Into::into),
            PROT_WRITE,
            &self.write_slice_page_prot_access,
            &mut is_not_trap,
            &mut trap_code,
        );

        (is_not_trap, trap_code)
    }
}

#[derive(Default)]
pub struct EdDecompressChip<E, M: TrustMode> {
    _marker: PhantomData<(E, M)>,
}

impl<E: EdwardsParameters, M: TrustMode> EdDecompressChip<E, M> {
    pub const fn new() -> Self {
        Self { _marker: PhantomData }
    }
}

impl<F: PrimeField32, E: EdwardsParameters, M: TrustMode> MachineAir<F> for EdDecompressChip<E, M> {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        if M::IS_TRUSTED {
            "EdDecompress"
        } else {
            "EdDecompressUser"
        }
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return Some(0);
        }
        let nb_rows = input.get_precompile_events(SyscallCode::ED_DECOMPRESS).len();
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

        let width = <EdDecompressChip<E, M> as BaseAir<F>>::width(self);
        let padded_nb_rows =
            <EdDecompressChip<E, M> as MachineAir<F>>::num_rows(self, input).unwrap();
        let events = input.get_precompile_events(SyscallCode::ED_DECOMPRESS);
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

        values.chunks_mut(width).enumerate().for_each(|(idx, row)| {
            let (_, event) = &events[idx];
            let event = if let PrecompileEvent::EdDecompress(event) = event {
                event
            } else {
                unreachable!();
            };
            let mut is_not_trap = true;
            let mut trap_code = 0;
            if !M::IS_TRUSTED {
                let cols: &mut EdDecompressCols<F, UserMode> = row.borrow_mut();
                let mut new_byte_lookup_events = Vec::new();
                EdDecompressCols::<F, UserMode>::populate_page_prot(
                    cols,
                    event,
                    &mut new_byte_lookup_events,
                    &mut is_not_trap,
                    &mut trap_code,
                );
                output.add_byte_lookup_events(new_byte_lookup_events);
            }
            let cols: &mut EdDecompressCols<F, M> = row.borrow_mut();
            cols.populate::<E::BaseField, E>(event.clone(), output, is_not_trap);
        });

        for idx in num_event_rows..padded_nb_rows {
            let row_start = idx * width;
            let row = unsafe {
                core::slice::from_raw_parts_mut(buffer[row_start..].as_mut_ptr() as *mut F, width)
            };
            let cols: &mut EdDecompressCols<F, M> = row.borrow_mut();
            let zero = BigUint::zero();
            cols.populate_field_ops::<E>(&mut vec![], &zero);
        }
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::ED_DECOMPRESS).is_empty()
                && (M::IS_TRUSTED != shard.program.enable_untrusted_programs)
        }
    }
}

impl<F, E: EdwardsParameters, M: TrustMode> BaseAir<F> for EdDecompressChip<E, M> {
    fn width(&self) -> usize {
        if M::IS_TRUSTED {
            NUM_ED_DECOMPRESS_COLS_SUPERVISOR
        } else {
            NUM_ED_DECOMPRESS_COLS_USER
        }
    }
}

impl<AB, E: EdwardsParameters, M: TrustMode> Air<AB> for EdDecompressChip<E, M>
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &EdDecompressCols<AB::Var, M> = (*local).borrow();

        let (mut is_trap, mut trap_code) = (local.is_real.into(), AB::Expr::zero());

        if !M::IS_TRUSTED {
            let local = main.row_slice(0);
            let local: &EdDecompressCols<AB::Var, UserMode> = (*local).borrow();
            #[cfg(not(feature = "mprotect"))]
            builder.assert_zero(local.is_real);
            (is_trap, trap_code) = local.eval_page_prot::<AB, E>(builder);
        }

        local.eval::<AB, E::BaseField, E>(builder, is_trap, trap_code);

        #[cfg(feature = "mprotect")]
        builder.assert_eq(
            builder.extract_public_values().is_untrusted_programs_enabled,
            AB::Expr::from_bool(!M::IS_TRUSTED),
        );
    }
}

#[cfg(test)]
pub mod tests {
    use std::sync::Arc;

    use sp1_core_executor::Program;
    use test_artifacts::ED_DECOMPRESS_ELF;

    use crate::{io::SP1Stdin, utils};

    #[tokio::test(flavor = "multi_thread")]
    async fn test_ed_decompress() {
        utils::setup_logger();
        let program = Program::from(&ED_DECOMPRESS_ELF).unwrap();
        let stdin = SP1Stdin::new();
        utils::run_test(Arc::new(program), stdin).await.unwrap();
    }
}
