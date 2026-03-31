use crate::{
    air::SP1CoreAirBuilder,
    memory::MemoryAccessCols,
    operations::{AddrAddOperation, SP1FieldWordRangeChecker, SyscallAddrOperation},
    utils::next_multiple_of_32,
};
use hashbrown::HashMap;
use itertools::Itertools;
use rayon::iter::{IndexedParallelIterator, ParallelBridge, ParallelIterator};
use slop_air::{Air, AirBuilder, BaseAir, PairBuilder};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use slop_maybe_rayon::prelude::ParallelSliceMut;
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord, MemoryRecordEnum, PrecompileEvent},
    ExecutionRecord, Program, SyscallCode,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{
    air::{InteractionScope, MachineAir},
    operations::poseidon2::{permutation::Poseidon2Cols, Poseidon2Operation},
    Word,
};
use std::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, MaybeUninit},
};

/// The number of columns in Poseidon2Cols.
const NUM_COLS: usize = size_of::<Poseidon2Cols2<u8>>();

/// Poseidon2 precompile chip.
#[derive(Default)]
pub struct Poseidon2Chip;

impl Poseidon2Chip {
    pub const fn new() -> Self {
        Self
    }
}

/// A set of columns for the Poseidon2 operation.
#[derive(Clone, AlignedBorrow)]
#[repr(C)]
pub struct Poseidon2Cols2<T: Copy> {
    /// The high bits of the clk of the syscall.
    pub clk_high: T,

    /// The low bits of the clk of the syscall.
    pub clk_low: T,

    /// The pointer to the input/output array.
    pub ptr: SyscallAddrOperation<T>,

    /// The address operations for the 8 words (16 u32s packed as u64s).
    pub addrs: [AddrAddOperation<T>; 8],

    /// Memory columns for the input/output (16 u32s packed as u64s).
    pub memory: [MemoryAccessCols<T>; 8],

    /// Hash result (16 u32s packed as u64s).
    pub hash_result: [Word<T>; 8],

    /// Range checkers for the hash result (16 u32s).
    pub hash_result_range_checkers: [SP1FieldWordRangeChecker<T>; 16],

    /// Range checkers for the input (16 u32s).
    pub input_range_checkers: [SP1FieldWordRangeChecker<T>; 16],

    /// The Poseidon2 operation columns.
    pub poseidon2_operation: Poseidon2Operation<T>,

    /// Whether this row is real.
    pub is_real: T,
}

impl<F: PrimeField32> MachineAir<F> for Poseidon2Chip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> &'static str {
        "Poseidon2"
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = input.get_precompile_events(SyscallCode::POSEIDON2).len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_multiple_of_32(nb_rows, size_log2);
        Some(padded_nb_rows)
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        // Generate the trace rows & corresponding records for each event.
        let events = input.get_precompile_events(SyscallCode::POSEIDON2);
        let num_event_rows = events.len();
        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);
        let padded_nb_rows = <Poseidon2Chip as MachineAir<F>>::num_rows(self, input).unwrap();

        unsafe {
            let padding_start = num_event_rows * NUM_COLS;
            let padding_size = (padded_nb_rows - num_event_rows) * NUM_COLS;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values =
            unsafe { core::slice::from_raw_parts_mut(buffer_ptr, padded_nb_rows * NUM_COLS) };

        values.par_chunks_mut(chunk_size * NUM_COLS).enumerate().for_each(|(i, rows)| {
            rows.chunks_mut(NUM_COLS).enumerate().for_each(|(j, row)| {
                unsafe {
                    core::ptr::write_bytes(row.as_mut_ptr(), 0, NUM_COLS);
                }
                let idx = i * chunk_size + j;
                let cols: &mut Poseidon2Cols2<F> = row.borrow_mut();

                if idx < events.len() {
                    let mut byte_lookup_events = Vec::new();
                    let event = if let PrecompileEvent::POSEIDON2(event) = &events[idx].1 {
                        event
                    } else {
                        unreachable!()
                    };

                    // Assign basic values to the columns.
                    cols.is_real = F::one();

                    cols.clk_high = F::from_canonical_u32((event.clk >> 24) as u32);
                    cols.clk_low = F::from_canonical_u32((event.clk & 0xFFFFFF) as u32);

                    cols.ptr.populate(&mut byte_lookup_events, event.ptr, 64);

                    // Populate memory columns for the 8 u64 words.
                    for i in 0..8 {
                        cols.addrs[i].populate(&mut byte_lookup_events, event.ptr, 8 * i as u64);

                        let memory_record = MemoryRecordEnum::Write(event.memory_records[i]);
                        cols.memory[i].populate(memory_record, &mut byte_lookup_events);
                        cols.hash_result[i] = Word::from(event.memory_records[i].value);

                        cols.hash_result_range_checkers[2 * i].populate(
                            Word([
                                cols.hash_result[i][0],
                                cols.hash_result[i][1],
                                F::zero(),
                                F::zero(),
                            ]),
                            &mut byte_lookup_events,
                        );
                        cols.hash_result_range_checkers[2 * i + 1].populate(
                            Word([
                                cols.hash_result[i][2],
                                cols.hash_result[i][3],
                                F::zero(),
                                F::zero(),
                            ]),
                            &mut byte_lookup_events,
                        );
                    }

                    // Extract the input values from memory.
                    let posiedon_input: [F; 16] = {
                        let mut values = [F::zero(); 16];
                        for i in 0..8 {
                            let val = event.memory_records[i].prev_value;
                            let val_lo = val as u32;
                            let val_hi = (val >> 32) as u32;
                            values[2 * i] = F::from_canonical_u32(val_lo);
                            values[2 * i + 1] = F::from_canonical_u32(val_hi);
                            cols.input_range_checkers[2 * i]
                                .populate(Word::from(val_lo), &mut byte_lookup_events);
                            cols.input_range_checkers[2 * i + 1]
                                .populate(Word::from(val_hi), &mut byte_lookup_events);
                        }
                        values
                    };

                    // Extract the output values that will be written.
                    let poseidon_output: [F; 16] = {
                        let mut values = [F::zero(); 16];
                        for i in 0..8 {
                            let val = event.memory_records[i].value;
                            values[2 * i] = F::from_canonical_u32(val as u32);
                            values[2 * i + 1] = F::from_canonical_u32((val >> 32) as u32);
                        }
                        values
                    };

                    // Populate the Poseidon2 operation.
                    cols.poseidon2_operation =
                        sp1_hypercube::operations::poseidon2::trace::populate_perm_deg3(
                            posiedon_input,
                            Some(poseidon_output),
                        );
                } else {
                    // Populate with dummy Poseidon2 operation for padding rows.
                    let dummy_input = [F::zero(); 16];
                    cols.poseidon2_operation =
                        sp1_hypercube::operations::poseidon2::trace::populate_perm_deg3(
                            dummy_input,
                            None,
                        );
                }
            });
        });
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let events = input.get_precompile_events(SyscallCode::POSEIDON2);
        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);
        let event_iter = events.chunks(chunk_size);

        let blu_batches = event_iter
            .par_bridge()
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, isize> = HashMap::new();
                events.iter().for_each(|event| {
                    let mut row = [F::zero(); NUM_COLS];
                    let cols: &mut Poseidon2Cols2<F> = row.as_mut_slice().borrow_mut();

                    let event = if let PrecompileEvent::POSEIDON2(event) = &event.1 {
                        event
                    } else {
                        unreachable!()
                    };

                    cols.ptr.populate(&mut blu, event.ptr, 64);
                    // Populate memory columns for the 8 u64 words.
                    for i in 0..8 {
                        cols.addrs[i].populate(&mut blu, event.ptr, 8 * i as u64);

                        let memory_record = MemoryRecordEnum::Write(event.memory_records[i]);
                        cols.memory[i].populate(memory_record, &mut blu);
                        cols.hash_result[i] = Word::from(event.memory_records[i].value);

                        blu.add_u16_range_checks_field(&cols.hash_result[i].0);
                        cols.hash_result_range_checkers[2 * i].populate(
                            Word([
                                cols.hash_result[i][0],
                                cols.hash_result[i][1],
                                F::zero(),
                                F::zero(),
                            ]),
                            &mut blu,
                        );
                        cols.hash_result_range_checkers[2 * i + 1].populate(
                            Word([
                                cols.hash_result[i][2],
                                cols.hash_result[i][3],
                                F::zero(),
                                F::zero(),
                            ]),
                            &mut blu,
                        );
                    }

                    // Extract the input values from memory.
                    for i in 0..8 {
                        let val = event.memory_records[i].prev_value;
                        let val_lo = val as u32;
                        let val_hi = (val >> 32) as u32;
                        blu.add_u16_range_checks_field::<F>(&Word::from(val).0);
                        cols.input_range_checkers[2 * i].populate(Word::from(val_lo), &mut blu);
                        cols.input_range_checkers[2 * i + 1].populate(Word::from(val_hi), &mut blu);
                    }
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
            !shard.get_precompile_events(SyscallCode::POSEIDON2).is_empty()
        }
    }
}

impl<F> BaseAir<F> for Poseidon2Chip {
    fn width(&self) -> usize {
        NUM_COLS
    }
}

impl<AB> Air<AB> for Poseidon2Chip
where
    AB: SP1CoreAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Poseidon2Cols2<AB::Var> = (*local).borrow();

        // Evaluate the pointer.
        let ptr = SyscallAddrOperation::<AB::F>::eval(builder, 64, local.ptr, local.is_real.into());

        // Evaluate the address.
        for i in 0..local.addrs.len() {
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([ptr[0].into(), ptr[1].into(), ptr[2].into(), AB::Expr::zero()]),
                Word::from(8 * i as u64),
                local.addrs[i],
                local.is_real.into(),
            );
        }

        // Evaluate memory access: read input, write output at the same addresses.
        builder.eval_memory_access_slice_write(
            local.clk_high,
            local.clk_low.into(),
            &local.addrs.map(|addr| addr.value.map(Into::into)),
            &local.memory,
            local.hash_result.to_vec(),
            local.is_real,
        );

        // Get the input values from memory (prev_value).
        let input_u64s: Vec<Word<AB::Var>> =
            local.memory.iter().map(|access| access.prev_value).collect();

        // Convert u64s to u32s for Poseidon2 (16 u32 values).
        let input: [AB::Expr; 16] = {
            let mut values = core::array::from_fn(|_| AB::Expr::zero());
            for i in 0..8 {
                values[2 * i] =
                    input_u64s[i][0] + input_u64s[i][1] * AB::F::from_canonical_u32(1 << 16);
                values[2 * i + 1] =
                    input_u64s[i][2] + input_u64s[i][3] * AB::F::from_canonical_u32(1 << 16);
                // Range check the input values.
                builder.slice_range_check_u16(&input_u64s[i].0, local.is_real);

                SP1FieldWordRangeChecker::<AB::F>::range_check(
                    builder,
                    Word([
                        input_u64s[i][0].into(),
                        input_u64s[i][1].into(),
                        AB::Expr::zero(),
                        AB::Expr::zero(),
                    ]),
                    local.input_range_checkers[2 * i],
                    local.is_real.into(),
                );
                SP1FieldWordRangeChecker::<AB::F>::range_check(
                    builder,
                    Word([
                        input_u64s[i][2].into(),
                        input_u64s[i][3].into(),
                        AB::Expr::zero(),
                        AB::Expr::zero(),
                    ]),
                    local.input_range_checkers[2 * i + 1],
                    local.is_real.into(),
                );
            }
            values
        };

        // Convert u64s to u32s for Poseidon2 (16 u32 values).
        let output: [AB::Expr; 16] = {
            let mut values = core::array::from_fn(|_| AB::Expr::zero());
            for i in 0..8 {
                values[2 * i] = local.hash_result[i][0]
                    + local.hash_result[i][1] * AB::F::from_canonical_u32(1 << 16);
                values[2 * i + 1] = local.hash_result[i][2]
                    + local.hash_result[i][3] * AB::F::from_canonical_u32(1 << 16);
                // Range check the hash result values.
                builder.slice_range_check_u16(&local.hash_result[i].0, local.is_real);

                SP1FieldWordRangeChecker::<AB::F>::range_check(
                    builder,
                    Word([
                        local.hash_result[i][0].into(),
                        local.hash_result[i][1].into(),
                        AB::Expr::zero(),
                        AB::Expr::zero(),
                    ]),
                    local.hash_result_range_checkers[2 * i],
                    local.is_real.into(),
                );
                SP1FieldWordRangeChecker::<AB::F>::range_check(
                    builder,
                    Word([
                        local.hash_result[i][2].into(),
                        local.hash_result[i][3].into(),
                        AB::Expr::zero(),
                        AB::Expr::zero(),
                    ]),
                    local.hash_result_range_checkers[2 * i + 1],
                    local.is_real.into(),
                );
            }

            values
        };

        // Evaluate the Poseidon2 permutation constraints.
        // We need to constrain that the permutation correctly transforms input to output.
        // First, verify the input matches what we expect from the permutation.
        let perm_input = &local.poseidon2_operation.permutation.external_rounds_state()[0];
        for i in 0..16 {
            builder.when(local.is_real).assert_eq(perm_input[i], input[i].clone());
        }

        // Evaluate external rounds.
        for r in 0..sp1_hypercube::operations::poseidon2::NUM_EXTERNAL_ROUNDS {
            sp1_hypercube::operations::poseidon2::air::eval_external_round(
                builder,
                &local.poseidon2_operation.permutation,
                r,
            );
        }

        // Evaluate internal rounds.
        sp1_hypercube::operations::poseidon2::air::eval_internal_rounds(
            builder,
            &local.poseidon2_operation.permutation,
        );

        // Verify the output matches the permutation result.
        let perm_output = local.poseidon2_operation.permutation.perm_output();
        for i in 0..16 {
            builder.when(local.is_real).assert_eq(perm_output[i], output[i].clone());
        }

        // Receive the syscall.
        builder.receive_syscall(
            local.clk_high,
            local.clk_low.into(),
            AB::F::from_canonical_u32(SyscallCode::POSEIDON2.syscall_id()),
            ptr.map(Into::into),
            [AB::Expr::zero(), AB::Expr::zero(), AB::Expr::zero()],
            local.is_real,
            InteractionScope::Local,
        );

        // Assert that is_real is a boolean.
        builder.assert_bool(local.is_real);
    }
}
