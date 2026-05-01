use crate::{
    air::SP1CoreAirBuilder,
    memory::{MemoryAccessCols, MemoryAccessColsU8},
    operations::{
        field::field_op::FieldOpCols, AddrAddOperation, AddressSlicePageProtOperation,
        SyscallAddrOperation,
    },
    utils::{limbs_to_words, next_multiple_of_32, words_to_bytes_le},
    SupervisorMode, TrustMode, UserMode,
};
use itertools::Itertools;
use num::{BigUint, One, Zero};
use slop_air::{Air, AirBuilder, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use sp1_core_executor::{
    events::{ByteRecord, FieldOperation, MemoryRecordEnum, PrecompileEvent},
    ExecutionRecord, Program, Register, SyscallCode,
};
use sp1_curves::{
    params::{Limbs, NumLimbs, NumWords},
    uint256::U256Field,
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
use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    mem::{size_of, MaybeUninit},
};
use typenum::Unsigned;

const U256_NUM_WORDS: usize = 4;
const U2048_NUM_WORDS: usize = 32;

pub const fn num_u256x2048_mul_cols_supervisor() -> usize {
    size_of::<U256x2048MulCols<u8, SupervisorMode>>()
}

pub const fn num_u256x2048_mul_cols_user() -> usize {
    size_of::<U256x2048MulCols<u8, UserMode>>()
}

#[derive(Default)]
pub struct U256x2048MulChip<M: TrustMode> {
    _marker: PhantomData<M>,
}

impl<M: TrustMode> U256x2048MulChip<M> {
    pub const fn new() -> Self {
        Self { _marker: PhantomData }
    }
}
type WordsFieldElement = <U256Field as NumWords>::WordsFieldElement;
const WORDS_FIELD_ELEMENT: usize = WordsFieldElement::USIZE;
const LO_REGISTER: u64 = Register::X12 as u64;
const HI_REGISTER: u64 = Register::X13 as u64;

/// A set of columns for the U256x2048Mul operation.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct U256x2048MulCols<T, M: TrustMode> {
    /// The high bits of the clk of the syscall.
    pub clk_high: T,

    /// The low bits of the clk of the syscall.
    pub clk_low: T,

    /// The pointer to the first input.
    pub a_ptr: SyscallAddrOperation<T>,

    /// The pointer to the second input.
    pub b_ptr: SyscallAddrOperation<T>,

    pub lo_ptr: SyscallAddrOperation<T>,
    pub hi_ptr: SyscallAddrOperation<T>,

    pub a_addrs: [AddrAddOperation<T>; WORDS_FIELD_ELEMENT],
    pub b_addrs: [AddrAddOperation<T>; WORDS_FIELD_ELEMENT * 8],
    pub lo_addrs: [AddrAddOperation<T>; WORDS_FIELD_ELEMENT * 8],
    pub hi_addrs: [AddrAddOperation<T>; WORDS_FIELD_ELEMENT],

    pub lo_ptr_memory: MemoryAccessCols<T>,
    pub lo_ptr_memory_value: [T; 3],
    pub hi_ptr_memory: MemoryAccessCols<T>,
    pub hi_ptr_memory_value: [T; 3],

    // Memory columns.
    pub a_memory: [MemoryAccessColsU8<T>; WORDS_FIELD_ELEMENT],
    pub b_memory: [MemoryAccessColsU8<T>; WORDS_FIELD_ELEMENT * 8],
    pub lo_memory: [MemoryAccessCols<T>; WORDS_FIELD_ELEMENT * 8],
    pub hi_memory: [MemoryAccessCols<T>; WORDS_FIELD_ELEMENT],

    // Output values. We compute (x * y) % 2^2048 and (x * y) / 2^2048.
    pub a_mul_b1: FieldOpCols<T, U256Field>,
    pub ab2_plus_carry: FieldOpCols<T, U256Field>,
    pub ab3_plus_carry: FieldOpCols<T, U256Field>,
    pub ab4_plus_carry: FieldOpCols<T, U256Field>,
    pub ab5_plus_carry: FieldOpCols<T, U256Field>,
    pub ab6_plus_carry: FieldOpCols<T, U256Field>,
    pub ab7_plus_carry: FieldOpCols<T, U256Field>,
    pub ab8_plus_carry: FieldOpCols<T, U256Field>,
    pub is_real: T,

    pub address_slice_page_prot_access_a: M::SliceProtCols<T>,
    pub address_slice_page_prot_access_b: M::SliceProtCols<T>,
    pub address_slice_page_prot_access_lo: M::SliceProtCols<T>,
    pub address_slice_page_prot_access_hi: M::SliceProtCols<T>,
}

impl<F: PrimeField32, M: TrustMode> MachineAir<F> for U256x2048MulChip<M> {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> &'static str {
        if M::IS_TRUSTED {
            "U256XU2048Mul"
        } else {
            "U256XU2048MulUser"
        }
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return Some(0);
        }
        let nb_rows = input.get_precompile_events(SyscallCode::U256XU2048_MUL).len();
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

        let width = <U256x2048MulChip<M> as BaseAir<F>>::width(self);
        let padded_nb_rows = <U256x2048MulChip<M> as MachineAir<F>>::num_rows(self, input).unwrap();
        let events = input.get_precompile_events(SyscallCode::U256XU2048_MUL);
        let chunk_size = 1;
        let num_event_rows = events.len();

        unsafe {
            let padding_start = num_event_rows * width;
            let padding_size = (padded_nb_rows - num_event_rows) * width;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let buffer_as_slice =
            unsafe { core::slice::from_raw_parts_mut(buffer_ptr, num_event_rows * width) };

        let mut new_byte_lookup_events = Vec::new();

        buffer_as_slice.chunks_exact_mut(chunk_size * width).enumerate().for_each(|(i, rows)| {
            rows.chunks_mut(width).enumerate().for_each(|(j, row)| {
                let idx = i * chunk_size + j;
                if idx < events.len() {
                    let event = &events[idx].1;
                    let event = if let PrecompileEvent::U256xU2048Mul(event) = event {
                        event
                    } else {
                        unreachable!()
                    };

                    let cols: &mut U256x2048MulCols<F, M> = row.borrow_mut();
                    // Assign basic values to the columns.
                    cols.is_real = F::one();

                    cols.clk_high = F::from_canonical_u32((event.clk >> 24) as u32);
                    cols.clk_low = F::from_canonical_u32((event.clk & 0xFFFFFF) as u32);

                    cols.a_ptr.populate(&mut new_byte_lookup_events, event.a_ptr, 32);
                    cols.b_ptr.populate(&mut new_byte_lookup_events, event.b_ptr, 256);
                    cols.lo_ptr.populate(&mut new_byte_lookup_events, event.lo_ptr, 256);
                    cols.hi_ptr.populate(&mut new_byte_lookup_events, event.hi_ptr, 32);

                    let mut is_not_trap = true;
                    let mut trap_code = 0u8;

                    if !M::IS_TRUSTED {
                        let cols: &mut U256x2048MulCols<F, UserMode> = row.borrow_mut();
                        // Populate the address slice page prot access.
                        cols.address_slice_page_prot_access_a.populate(
                            &mut new_byte_lookup_events,
                            event.a_ptr,
                            event.a_ptr + ((U256_NUM_WORDS - 1) * 8) as u64,
                            event.clk,
                            PROT_READ,
                            &event.page_prot_records.read_a_page_prot_records,
                            &mut is_not_trap,
                            &mut trap_code,
                        );

                        cols.address_slice_page_prot_access_b.populate(
                            &mut new_byte_lookup_events,
                            event.b_ptr,
                            event.b_ptr + ((U2048_NUM_WORDS - 1) * 8) as u64,
                            event.clk + 1,
                            PROT_READ,
                            &event.page_prot_records.read_b_page_prot_records,
                            &mut is_not_trap,
                            &mut trap_code,
                        );

                        cols.address_slice_page_prot_access_lo.populate(
                            &mut new_byte_lookup_events,
                            event.lo_ptr,
                            event.lo_ptr + ((32 - 1) * 8) as u64,
                            event.clk + 2,
                            PROT_WRITE,
                            &event.page_prot_records.write_lo_page_prot_records,
                            &mut is_not_trap,
                            &mut trap_code,
                        );

                        cols.address_slice_page_prot_access_hi.populate(
                            &mut new_byte_lookup_events,
                            event.hi_ptr,
                            event.hi_ptr + ((4 - 1) * 8) as u64,
                            event.clk + 3,
                            PROT_WRITE,
                            &event.page_prot_records.write_hi_page_prot_records,
                            &mut is_not_trap,
                            &mut trap_code,
                        );
                    }

                    let cols: &mut U256x2048MulCols<F, M> = row.borrow_mut();

                    // Populate memory accesses for lo_ptr and hi_ptr.
                    let lo_ptr_memory_record = MemoryRecordEnum::Read(event.lo_ptr_memory);
                    let hi_ptr_memory_record = MemoryRecordEnum::Read(event.hi_ptr_memory);

                    assert_eq!(lo_ptr_memory_record.prev_value(), event.lo_ptr);
                    assert_eq!(hi_ptr_memory_record.prev_value(), event.hi_ptr);

                    cols.lo_ptr_memory.populate(lo_ptr_memory_record, &mut new_byte_lookup_events);
                    cols.lo_ptr_memory_value = [
                        F::from_canonical_u16((event.lo_ptr & 0xFFFF) as u16),
                        F::from_canonical_u16(((event.lo_ptr >> 16) & 0xFFFF) as u16),
                        F::from_canonical_u16(((event.lo_ptr >> 32) & 0xFFFF) as u16),
                    ];
                    cols.hi_ptr_memory.populate(hi_ptr_memory_record, &mut new_byte_lookup_events);
                    cols.hi_ptr_memory_value = [
                        F::from_canonical_u16((event.hi_ptr & 0xFFFF) as u16),
                        F::from_canonical_u16(((event.hi_ptr >> 16) & 0xFFFF) as u16),
                        F::from_canonical_u16(((event.hi_ptr >> 32) & 0xFFFF) as u16),
                    ];

                    // Populate memory columns.
                    for i in 0..WORDS_FIELD_ELEMENT {
                        cols.a_addrs[i].populate(
                            &mut new_byte_lookup_events,
                            event.a_ptr,
                            (i * 8) as u64,
                        );
                        if is_not_trap {
                            let record = MemoryRecordEnum::Read(event.a_memory_records[i]);
                            cols.a_memory[i].populate(record, &mut new_byte_lookup_events);
                        } else {
                            cols.a_memory[i] = MemoryAccessColsU8::default();
                        }
                    }
                    for i in 0..WORDS_FIELD_ELEMENT * 8 {
                        cols.b_addrs[i].populate(
                            &mut new_byte_lookup_events,
                            event.b_ptr,
                            (i * 8) as u64,
                        );
                        if is_not_trap {
                            let record = MemoryRecordEnum::Read(event.b_memory_records[i]);
                            cols.b_memory[i].populate(record, &mut new_byte_lookup_events);
                        } else {
                            cols.b_memory[i] = MemoryAccessColsU8::default();
                        }
                    }

                    for i in 0..WORDS_FIELD_ELEMENT * 8 {
                        cols.lo_addrs[i].populate(
                            &mut new_byte_lookup_events,
                            event.lo_ptr,
                            8 * i as u64,
                        );
                        if is_not_trap {
                            let record = MemoryRecordEnum::Write(event.lo_memory_records[i]);
                            cols.lo_memory[i].populate(record, &mut new_byte_lookup_events);
                        } else {
                            cols.lo_memory[i] = MemoryAccessCols::default();
                        }
                    }

                    for i in 0..WORDS_FIELD_ELEMENT {
                        cols.hi_addrs[i].populate(
                            &mut new_byte_lookup_events,
                            event.hi_ptr,
                            8 * i as u64,
                        );
                        if is_not_trap {
                            let record = MemoryRecordEnum::Write(event.hi_memory_records[i]);
                            cols.hi_memory[i].populate(record, &mut new_byte_lookup_events);
                        } else {
                            cols.hi_memory[i] = MemoryAccessCols::default();
                        }
                    }

                    let a = BigUint::from_bytes_le(&words_to_bytes_le::<32>(&event.a));
                    let b_array: [BigUint; 8] = event
                        .b
                        .chunks(4)
                        .map(|chunk| BigUint::from_bytes_le(&words_to_bytes_le::<32>(chunk)))
                        .collect::<Vec<_>>()
                        .try_into()
                        .unwrap();

                    let effective_modulus = BigUint::one() << 256;

                    let mut carries = vec![BigUint::zero(); 9];
                    let mut ab_plus_carry_cols = [
                        &mut cols.a_mul_b1,
                        &mut cols.ab2_plus_carry,
                        &mut cols.ab3_plus_carry,
                        &mut cols.ab4_plus_carry,
                        &mut cols.ab5_plus_carry,
                        &mut cols.ab6_plus_carry,
                        &mut cols.ab7_plus_carry,
                        &mut cols.ab8_plus_carry,
                    ];

                    for (i, col) in ab_plus_carry_cols.iter_mut().enumerate() {
                        let (_, carry) = col.populate_mul_and_carry(
                            &mut new_byte_lookup_events,
                            &a,
                            &b_array[i],
                            &carries[i],
                            &effective_modulus,
                        );
                        carries[i + 1] = carry;
                    }
                }
            })
        });

        for row in num_event_rows..padded_nb_rows {
            let row_start = row * width;
            let row = unsafe {
                core::slice::from_raw_parts_mut(buffer[row_start..].as_mut_ptr() as *mut F, width)
            };

            let cols: &mut U256x2048MulCols<F, M> = row.borrow_mut();

            let x = BigUint::zero();
            let y = BigUint::zero();
            let z = BigUint::zero();
            let modulus = BigUint::one() << 256;

            // Populate all the mul and carry columns with zero values.
            cols.a_mul_b1.populate(&mut vec![], &x, &y, FieldOperation::Mul);
            cols.ab2_plus_carry.populate_mul_and_carry(&mut vec![], &x, &y, &z, &modulus);
            cols.ab3_plus_carry.populate_mul_and_carry(&mut vec![], &x, &y, &z, &modulus);
            cols.ab4_plus_carry.populate_mul_and_carry(&mut vec![], &x, &y, &z, &modulus);
            cols.ab5_plus_carry.populate_mul_and_carry(&mut vec![], &x, &y, &z, &modulus);
            cols.ab6_plus_carry.populate_mul_and_carry(&mut vec![], &x, &y, &z, &modulus);
            cols.ab7_plus_carry.populate_mul_and_carry(&mut vec![], &x, &y, &z, &modulus);
            cols.ab8_plus_carry.populate_mul_and_carry(&mut vec![], &x, &y, &z, &modulus);
        }

        output.add_byte_lookup_events(new_byte_lookup_events);
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if M::IS_TRUSTED == shard.program.enable_untrusted_programs {
            return false;
        }

        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::U256XU2048_MUL).is_empty()
        }
    }
}

impl<F, M: TrustMode> BaseAir<F> for U256x2048MulChip<M> {
    fn width(&self) -> usize {
        if M::IS_TRUSTED {
            num_u256x2048_mul_cols_supervisor()
        } else {
            num_u256x2048_mul_cols_user()
        }
    }
}

impl<AB, M: TrustMode> Air<AB> for U256x2048MulChip<M>
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &U256x2048MulCols<AB::Var, M> = (*local).borrow();

        // Assert that is_real is a boolean.
        builder.assert_bool(local.is_real);

        let a_ptr =
            SyscallAddrOperation::<AB::F>::eval(builder, 32, local.a_ptr, local.is_real.into());
        let b_ptr =
            SyscallAddrOperation::<AB::F>::eval(builder, 256, local.b_ptr, local.is_real.into());
        let lo_ptr =
            SyscallAddrOperation::<AB::F>::eval(builder, 256, local.lo_ptr, local.is_real.into());
        let hi_ptr =
            SyscallAddrOperation::<AB::F>::eval(builder, 32, local.hi_ptr, local.is_real.into());

        // Evaluate that the lo_ptr and hi_ptr are read from the correct memory locations.
        builder.eval_memory_access_read(
            local.clk_high,
            local.clk_low.into(),
            &[AB::Expr::from_canonical_u64(LO_REGISTER), AB::Expr::zero(), AB::Expr::zero()],
            local.lo_ptr_memory,
            local.is_real.into(),
        );

        builder.eval_memory_access_read(
            local.clk_high,
            local.clk_low.into(),
            &[AB::Expr::from_canonical_u64(HI_REGISTER), AB::Expr::zero(), AB::Expr::zero()],
            local.hi_ptr_memory,
            local.is_real.into(),
        );

        // a_addrs[i] = a_ptr + 8 * i
        for i in 0..local.a_addrs.len() {
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([a_ptr[0].into(), a_ptr[1].into(), a_ptr[2].into(), AB::Expr::zero()]),
                Word::from(8 * i as u64),
                local.a_addrs[i],
                local.is_real.into(),
            );
        }

        // b_addrs[i] = b_ptr + 8 * i
        for i in 0..local.b_addrs.len() {
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([b_ptr[0].into(), b_ptr[1].into(), b_ptr[2].into(), AB::Expr::zero()]),
                Word::from(8 * i as u64),
                local.b_addrs[i],
                local.is_real.into(),
            );
        }

        // lo_addrs[i] = lo_ptr + 8 * i
        for i in 0..local.lo_addrs.len() {
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([lo_ptr[0].into(), lo_ptr[1].into(), lo_ptr[2].into(), AB::Expr::zero()]),
                Word::from(8 * i as u64),
                local.lo_addrs[i],
                local.is_real.into(),
            );
        }

        // hi_addrs[i] = hi_ptr + 8 * i
        for i in 0..local.hi_addrs.len() {
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([hi_ptr[0].into(), hi_ptr[1].into(), hi_ptr[2].into(), AB::Expr::zero()]),
                Word::from(8 * i as u64),
                local.hi_addrs[i],
                local.is_real.into(),
            );
        }

        let mut is_not_trap = local.is_real.into();
        let mut trap_code = AB::Expr::zero();

        // Evaluate the page prot accesses only for user mode.
        if !M::IS_TRUSTED {
            let local = main.row_slice(0);
            let local: &U256x2048MulCols<AB::Var, UserMode> = (*local).borrow();

            #[cfg(not(feature = "mprotect"))]
            builder.assert_zero(local.is_real);

            AddressSlicePageProtOperation::<AB::F>::eval(
                builder,
                local.clk_high.into(),
                local.clk_low.into(),
                &a_ptr.map(Into::into),
                &local.a_addrs.last().unwrap().value.map(Into::into),
                PROT_READ,
                &local.address_slice_page_prot_access_a,
                &mut is_not_trap,
                &mut trap_code,
            );

            AddressSlicePageProtOperation::<AB::F>::eval(
                builder,
                local.clk_high.into(),
                local.clk_low.into() + AB::Expr::from_canonical_u8(1),
                &b_ptr.map(Into::into),
                &local.b_addrs.last().unwrap().value.map(Into::into),
                PROT_READ,
                &local.address_slice_page_prot_access_b,
                &mut is_not_trap,
                &mut trap_code,
            );

            AddressSlicePageProtOperation::<AB::F>::eval(
                builder,
                local.clk_high.into(),
                local.clk_low.into() + AB::Expr::from_canonical_u8(2),
                &lo_ptr.map(Into::into),
                &local.lo_addrs.last().unwrap().value.map(Into::into),
                PROT_WRITE,
                &local.address_slice_page_prot_access_lo,
                &mut is_not_trap,
                &mut trap_code,
            );

            AddressSlicePageProtOperation::<AB::F>::eval(
                builder,
                local.clk_high.into(),
                local.clk_low.into() + AB::Expr::from_canonical_u8(3),
                &hi_ptr.map(Into::into),
                &local.hi_addrs.last().unwrap().value.map(Into::into),
                PROT_WRITE,
                &local.address_slice_page_prot_access_hi,
                &mut is_not_trap,
                &mut trap_code,
            );
        }

        // Receive the arguments.
        builder.receive_syscall(
            local.clk_high,
            local.clk_low,
            AB::F::from_canonical_u32(SyscallCode::U256XU2048_MUL.syscall_id()),
            trap_code.clone(),
            a_ptr.map(Into::into),
            b_ptr.map(Into::into),
            local.is_real,
            InteractionScope::Local,
        );

        // Evaluate the memory accesses for a_memory and b_memory.
        builder.eval_memory_access_slice_read(
            local.clk_high,
            local.clk_low.into(),
            &local.a_addrs.map(|addr| addr.value.map(Into::into)),
            &local.a_memory.iter().map(|access| access.memory_access).collect_vec(),
            is_not_trap.clone(),
        );

        builder.eval_memory_access_slice_read(
            local.clk_high,
            local.clk_low.into() + AB::Expr::one(),
            &local.b_addrs.map(|addr| addr.value.map(Into::into)),
            &local.b_memory.iter().map(|access| access.memory_access).collect_vec(),
            is_not_trap.clone(),
        );

        let a_limbs_vec = builder.generate_limbs(&local.a_memory, is_not_trap.clone());
        let a_limbs: Limbs<AB::Expr, <U256Field as NumLimbs>::Limbs> =
            Limbs(a_limbs_vec.try_into().expect("failed to convert limbs"));

        // Iterate through chunks of 8 for b_memory and convert each chunk to its limbs.
        let b_limb_array: Vec<Limbs<AB::Expr, <U256Field as NumLimbs>::Limbs>> = local
            .b_memory
            .chunks(4)
            .map(|access| {
                Limbs(
                    builder
                        .generate_limbs(access, is_not_trap.clone())
                        .try_into()
                        .expect("failed to convert limbs"),
                )
            })
            .collect::<Vec<_>>();

        let mut coeff_2_256 = Vec::new();
        coeff_2_256.resize(32, AB::Expr::zero());
        coeff_2_256.push(AB::Expr::one());
        let modulus_polynomial: Polynomial<AB::Expr> = Polynomial::from_coefficients(&coeff_2_256);

        // Evaluate that each of the mul and carry columns are valid.
        let outputs = [
            &local.a_mul_b1,
            &local.ab2_plus_carry,
            &local.ab3_plus_carry,
            &local.ab4_plus_carry,
            &local.ab5_plus_carry,
            &local.ab6_plus_carry,
            &local.ab7_plus_carry,
            &local.ab8_plus_carry,
        ];

        outputs[0].eval_mul_and_carry(
            builder,
            &a_limbs,
            &b_limb_array[0],
            &Polynomial::from_coefficients(&[AB::Expr::zero()]),
            &modulus_polynomial,
            local.is_real,
        );

        for i in 1..outputs.len() {
            outputs[i].eval_mul_and_carry(
                builder,
                &a_limbs,
                &b_limb_array[i],
                &outputs[i - 1].carry,
                &modulus_polynomial,
                local.is_real,
            );
        }

        // Evaluate the memory accesses for lo_memory and hi_memory.
        let mut result_words = Vec::new();
        for i in 0..8 {
            let output_words = limbs_to_words::<AB>(outputs[i].result.0.to_vec());
            result_words.extend(output_words);
        }

        builder.eval_memory_access_slice_write(
            local.clk_high,
            local.clk_low + AB::Expr::from_canonical_u8(2),
            &local.lo_addrs.map(|addr| addr.value.map(Into::into)),
            &local.lo_memory,
            result_words,
            is_not_trap.clone(),
        );

        let output_carry_words = limbs_to_words::<AB>(outputs[outputs.len() - 1].carry.0.to_vec());
        builder.eval_memory_access_slice_write(
            local.clk_high,
            local.clk_low + AB::Expr::from_canonical_u8(3),
            &local.hi_addrs.map(|addr| addr.value.map(Into::into)),
            &local.hi_memory,
            output_carry_words,
            is_not_trap.clone(),
        );

        // Constrain that the lo_ptr is the value of lo_ptr_memory.
        for i in 0..3 {
            builder
                .when(local.is_real)
                .assert_eq(local.lo_ptr.addr[i], local.lo_ptr_memory.prev_value[i]);
        }
        builder.assert_eq(local.lo_ptr_memory.prev_value[3], AB::Expr::zero());

        // Constrain that the hi_ptr is the value of hi_ptr_memory.
        for i in 0..3 {
            builder
                .when(local.is_real)
                .assert_eq(local.hi_ptr.addr[i], local.hi_ptr_memory.prev_value[i]);
        }
        builder.assert_eq(local.hi_ptr_memory.prev_value[3], AB::Expr::zero());

        #[cfg(feature = "mprotect")]
        builder.assert_eq(
            builder.extract_public_values().is_untrusted_programs_enabled,
            AB::Expr::from_bool(!M::IS_TRUSTED),
        );
    }
}
