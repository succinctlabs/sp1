use hashbrown::HashMap;
use itertools::Itertools;
use slop_air::{Air, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use slop_maybe_rayon::prelude::{
    IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator,
};
use sp1_core_executor::{
    events::{
        ByteLookupEvent, ByteRecord, InstructionFetchEvent, MemInstrEvent, MemoryAccessPosition,
        MemoryRecordEnum,
    },
    ByteOpcode, ExecutionRecord, Program,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::air::MachineAir;
use sp1_primitives::consts::{PROT_EXEC, PROT_READ, PROT_WRITE};
use std::{
    borrow::{Borrow, BorrowMut},
    mem::MaybeUninit,
};

use crate::{air::SP1CoreAirBuilder, operations::PageProtOperation, utils::next_multiple_of_32};

// Used to ensure address is aligned to page, clears out lowest 3 bits
const BITMASK_CLEAR_LOWEST_THREE_BITS: u64 = 0xFFFFFFFFFFFFFFF8;

pub const NUM_PAGE_PROT_ENTRIES_PER_ROW: usize = 4;
pub(crate) const NUM_PAGE_PROT_COLS: usize = size_of::<PageProtCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct SinglePageProtCols<T: Copy> {
    /// The clock of the memory access.
    pub clk_high: T,
    pub clk_low: T,

    /// The address of the memory access.
    pub addr: [T; 3],

    /// The permissions of the page.
    pub permissions: T,

    /// Whether or not the row is a real row or a padding row.
    pub is_real: T,

    /// The page prot operation.
    pub page_prot_op: PageProtOperation<T>,
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct PageProtCols<T: Copy> {
    page_prot_entries: [SinglePageProtCols<T>; NUM_PAGE_PROT_ENTRIES_PER_ROW],
}

#[derive(Default)]
pub struct PageProtChip;

impl<F> BaseAir<F> for PageProtChip {
    fn width(&self) -> usize {
        NUM_PAGE_PROT_COLS
    }
}

fn nb_rows(count: usize) -> usize {
    if NUM_PAGE_PROT_ENTRIES_PER_ROW > 1 {
        count.div_ceil(NUM_PAGE_PROT_ENTRIES_PER_ROW)
    } else {
        count
    }
}

impl<F: PrimeField32> MachineAir<F> for PageProtChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        "PageProt"
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let mut count = 0;
        if input.public_values.is_untrusted_programs_enabled == 1 {
            count = input.memory_load_byte_events.len()
                + input.memory_store_byte_events.len()
                + input.memory_load_word_events.len()
                + input.memory_store_word_events.len()
                + input.memory_load_double_events.len()
                + input.memory_store_double_events.len()
                + input.memory_load_half_events.len()
                + input.memory_store_half_events.len()
                + input.memory_load_x0_events.len()
                + input.instruction_fetch_events.len();
        }

        let nb_rows = nb_rows(count);
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        Some(next_multiple_of_32(nb_rows, size_log2))
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        let mut events = vec![];

        if input.public_values.is_untrusted_programs_enabled == 1 {
            events = input
                .memory_load_byte_events
                .iter()
                .map(|e| Self::generate_page_prot_event(&e.0, true, false, false))
                .chain(
                    input
                        .memory_store_byte_events
                        .iter()
                        .map(|e| Self::generate_page_prot_event(&e.0, false, true, false)),
                )
                .chain(
                    input
                        .memory_load_word_events
                        .iter()
                        .map(|e| Self::generate_page_prot_event(&e.0, true, false, false)),
                )
                .chain(
                    input
                        .memory_store_word_events
                        .iter()
                        .map(|e| Self::generate_page_prot_event(&e.0, false, true, false)),
                )
                .chain(
                    input
                        .memory_load_double_events
                        .iter()
                        .map(|e| Self::generate_page_prot_event(&e.0, true, false, false)),
                )
                .chain(
                    input
                        .memory_store_double_events
                        .iter()
                        .map(|e| Self::generate_page_prot_event(&e.0, false, true, false)),
                )
                .chain(
                    input
                        .memory_load_half_events
                        .iter()
                        .map(|e| Self::generate_page_prot_event(&e.0, true, false, false)),
                )
                .chain(
                    input
                        .memory_store_half_events
                        .iter()
                        .map(|e| Self::generate_page_prot_event(&e.0, false, true, false)),
                )
                .chain(
                    input
                        .memory_load_x0_events
                        .iter()
                        .map(|e| Self::generate_page_prot_event(&e.0, true, false, false)),
                )
                .chain(input.instruction_fetch_events.iter().map(|e| {
                    let (mem_access, _) = e.1.untrusted_instruction.unwrap();
                    Self::generate_fetch_instruction_page_prot_event(
                        &e.0, mem_access, true, false, true,
                    )
                }))
                .collect_vec();
        }

        let nb_rows = nb_rows(events.len());
        let padded_nb_rows = <PageProtChip as MachineAir<F>>::num_rows(self, input).unwrap();

        unsafe {
            let padding_start = nb_rows * NUM_PAGE_PROT_COLS;
            let padding_size = (padded_nb_rows - nb_rows) * NUM_PAGE_PROT_COLS;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values =
            unsafe { core::slice::from_raw_parts_mut(buffer_ptr, nb_rows * NUM_PAGE_PROT_COLS) };

        let chunk_size = std::cmp::max(nb_rows / num_cpus::get(), 0) + 1;

        let mut chunks = values[..nb_rows * NUM_PAGE_PROT_COLS]
            .chunks_mut(chunk_size * NUM_PAGE_PROT_COLS)
            .collect::<Vec<_>>();

        let blu_events = chunks
            .par_iter_mut()
            .enumerate()
            .map(|(i, rows)| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();

                rows.chunks_mut(NUM_PAGE_PROT_COLS).enumerate().for_each(|(j, row)| {
                    unsafe {
                        core::ptr::write_bytes(row.as_mut_ptr(), 0, NUM_PAGE_PROT_COLS);
                    }
                    let idx = (i * chunk_size + j) * NUM_PAGE_PROT_ENTRIES_PER_ROW;
                    let cols: &mut PageProtCols<F> = row.borrow_mut();

                    for k in 0..NUM_PAGE_PROT_ENTRIES_PER_ROW {
                        let cols = &mut cols.page_prot_entries[k];
                        if idx + k < events.len() {
                            let event = &events[idx + k];
                            self.event_to_row(event, cols, &mut blu);
                        }
                    }
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_events.iter().collect_vec());
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            (shard.memory_load_byte_events.len()
                + shard.memory_store_byte_events.len()
                + shard.memory_load_word_events.len()
                + shard.memory_store_word_events.len()
                + shard.memory_load_double_events.len()
                + shard.memory_store_double_events.len()
                + shard.memory_load_half_events.len()
                + shard.memory_store_half_events.len()
                + shard.memory_load_x0_events.len()
                + shard.instruction_fetch_events.len()
                > 0)
                && shard.program.enable_untrusted_programs
        }
    }
}

impl<AB> Air<AB> for PageProtChip
where
    AB: SP1CoreAirBuilder,
    AB::Var: Sized,
    AB::F: PrimeField32,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &PageProtCols<AB::Var> = (*local).borrow();

        builder.assert_eq(
            builder.extract_public_values().is_untrusted_programs_enabled,
            AB::Expr::one(),
        );

        for local in local.page_prot_entries.iter() {
            // Assert that `is_real` is boolean.
            builder.assert_bool(local.is_real);

            #[cfg(not(feature = "mprotect"))]
            builder.assert_zero(local.is_real);

            // Ensure requested permission matches the set permission.
            builder.send_byte(
                AB::Expr::from_canonical_u8(ByteOpcode::AND as u8),
                local.permissions,
                local.permissions,
                local.page_prot_op.page_prot_access.prev_prot_bitmap,
                local.is_real,
            );

            // Receive the page prot access.
            builder.receive_page_prot(
                local.clk_high,
                local.clk_low,
                &local.addr.map(Into::into),
                local.permissions,
                local.is_real,
            );

            // Read the currently set page permissions.
            PageProtOperation::<AB::F>::eval(
                builder,
                local.clk_high.into(),
                local.clk_low.into(),
                &local.addr.map(Into::into),
                local.page_prot_op,
                local.is_real.into(),
            );
        }
    }
}

struct PageProtEvent {
    clk: u64,
    addr: u64,
    is_read: bool,
    is_write: bool,
    is_executable: bool,
    mem_access: MemoryRecordEnum,
}

impl PageProtChip {
    fn generate_page_prot_event(
        mem_instr_event: &MemInstrEvent,
        is_read: bool,
        is_write: bool,
        is_executable: bool,
    ) -> PageProtEvent {
        PageProtEvent {
            clk: mem_instr_event.clk + MemoryAccessPosition::Memory as u64,
            addr: (mem_instr_event.b.wrapping_add(mem_instr_event.c)
                & BITMASK_CLEAR_LOWEST_THREE_BITS) as u64,
            is_read,
            is_write,
            is_executable,
            mem_access: mem_instr_event.mem_access,
        }
    }

    fn generate_fetch_instruction_page_prot_event(
        untrusted_program_event: &InstructionFetchEvent,
        memory_record_enum: MemoryRecordEnum,
        is_read: bool,
        is_write: bool,
        is_executable: bool,
    ) -> PageProtEvent {
        PageProtEvent {
            clk: untrusted_program_event.clk,
            addr: (untrusted_program_event.pc & BITMASK_CLEAR_LOWEST_THREE_BITS) as u64,
            is_read,
            is_write,
            is_executable,
            mem_access: memory_record_enum,
        }
    }

    fn event_to_row<F: PrimeField32>(
        &self,
        event: &PageProtEvent,
        cols: &mut SinglePageProtCols<F>,
        blu: &mut HashMap<ByteLookupEvent, usize>,
    ) {
        cols.clk_high = F::from_canonical_u32((event.clk >> 24) as u32);
        cols.clk_low = F::from_canonical_u32((event.clk & 0xFFFFFF) as u32);

        let mut perm: u8 = 0;
        perm += (event.is_read as u8) * PROT_READ;
        perm += (event.is_write as u8) * PROT_WRITE;
        perm += (event.is_executable as u8) * PROT_EXEC;

        let set_perm = event.mem_access.previous_page_prot_record().unwrap().page_prot;

        blu.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::AND,
            a: perm as u16,
            b: perm,
            c: set_perm,
        });

        cols.permissions = F::from_canonical_u8(perm);
        cols.is_real = F::one();

        cols.addr = [
            F::from_canonical_u64(event.addr & 0xFFFF),
            F::from_canonical_u64((event.addr >> 16) & 0xFFFF),
            F::from_canonical_u64((event.addr >> 32) & 0xFFFF),
        ];

        cols.page_prot_op.populate(
            blu,
            event.addr,
            event.clk,
            &event.mem_access.previous_page_prot_record().unwrap(),
        );
    }
}
