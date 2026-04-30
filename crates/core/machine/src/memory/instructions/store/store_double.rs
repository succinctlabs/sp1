use crate::{
    adapter::{
        register::i_type::{ITypeReader, ITypeReaderImmutable, ITypeReaderImmutableInput},
        state::{CPUState, CPUStateInput},
    },
    air::{SP1CoreAirBuilder, SP1Operation},
    memory::MemoryAccessCols,
    operations::{AddressOperation, AddressOperationInput},
    utils::next_multiple_of_32,
};
use hashbrown::HashMap;
use itertools::Itertools;
use rayon::iter::{ParallelBridge, ParallelIterator};
use slop_air::{Air, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord, MemInstrEvent, MemoryAccessPosition},
    ExecutionRecord, Opcode, Program, CLK_INC, PC_INC,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::air::MachineAir;
use std::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, MaybeUninit},
};
use struct_reflection::{StructReflection, StructReflectionHelper};

#[derive(Default)]
pub struct StoreDoubleChip;

pub const NUM_STORE_DOUBLE_COLUMNS: usize = size_of::<StoreDoubleColumns<u8>>();

/// The column layout for memory store double instructions.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy, StructReflection)]
#[repr(C)]
pub struct StoreDoubleColumns<T> {
    /// The current shard, timestamp, program counter of the CPU.
    pub state: CPUState<T>,

    /// The adapter to read program and register information.
    pub adapter: ITypeReader<T>,

    /// Instance of `AddressOperation` to constrain the memory address.
    pub address_operation: AddressOperation<T>,

    /// Memory consistency columns for the memory access.
    pub memory_access: MemoryAccessCols<T>,

    /// Whether this is a real store word instruction.
    pub is_real: T,
}

impl<F> BaseAir<F> for StoreDoubleChip {
    fn width(&self) -> usize {
        NUM_STORE_DOUBLE_COLUMNS
    }
}

impl<F: PrimeField32> MachineAir<F> for StoreDoubleChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        "StoreDouble"
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = next_multiple_of_32(
            input.memory_store_double_events.len(),
            input.fixed_log2_rows::<F, _>(self),
        );
        Some(nb_rows)
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        let chunk_size =
            std::cmp::max((input.memory_store_double_events.len()) / num_cpus::get(), 1);
        let padded_nb_rows = <StoreDoubleChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let num_event_rows = input.memory_store_double_events.len();

        unsafe {
            let padding_start = num_event_rows * NUM_STORE_DOUBLE_COLUMNS;
            let padding_size = (padded_nb_rows - num_event_rows) * NUM_STORE_DOUBLE_COLUMNS;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe {
            core::slice::from_raw_parts_mut(buffer_ptr, padded_nb_rows * NUM_STORE_DOUBLE_COLUMNS)
        };

        let blu_events = values
            .chunks_mut(chunk_size * NUM_STORE_DOUBLE_COLUMNS)
            .enumerate()
            .par_bridge()
            .map(|(i, rows)| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                rows.chunks_mut(NUM_STORE_DOUBLE_COLUMNS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut StoreDoubleColumns<F> = row.borrow_mut();

                    if idx < input.memory_store_double_events.len() {
                        let event = &input.memory_store_double_events[idx];
                        self.event_to_row(&event.0, cols, &mut blu);
                        cols.state.populate(&mut blu, event.0.clk, event.0.pc);
                        cols.adapter.populate(&mut blu, event.1);
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
            !shard.memory_store_double_events.is_empty()
        }
    }

    fn column_names(&self) -> Vec<String> {
        StoreDoubleColumns::<F>::struct_reflection().unwrap()
    }
}

impl StoreDoubleChip {
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &MemInstrEvent,
        cols: &mut StoreDoubleColumns<F>,
        blu: &mut HashMap<ByteLookupEvent, usize>,
    ) {
        // Populate memory accesses for reading from memory.
        cols.memory_access.populate(event.mem_access, blu);
        cols.address_operation.populate(blu, event.b, event.c);
        cols.is_real = F::one();
    }
}

impl<AB> Air<AB> for StoreDoubleChip
where
    AB: SP1CoreAirBuilder,
    AB::Var: Sized,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &StoreDoubleColumns<AB::Var> = (*local).borrow();

        let clk_high = local.state.clk_high::<AB>();
        let clk_low = local.state.clk_low::<AB>();

        let opcode = AB::Expr::from_canonical_u32(Opcode::SD as u32);
        let funct3 = AB::Expr::from_canonical_u8(Opcode::SD.funct3().unwrap());
        let funct7 = AB::Expr::from_canonical_u8(Opcode::SD.funct7().unwrap_or(0));
        let base_opcode = AB::Expr::from_canonical_u32(Opcode::SD.base_opcode().0);
        let instr_type = AB::Expr::from_canonical_u32(Opcode::SD.instruction_type().0 as u32);

        builder.assert_bool(local.is_real);

        // Step 1. Compute the address, and check offsets and address bounds.
        let aligned_addr = <AddressOperation<AB::F> as SP1Operation<AB>>::eval(
            builder,
            AddressOperationInput::new(
                local.adapter.b().map(Into::into),
                local.adapter.c().map(Into::into),
                AB::Expr::zero(),
                AB::Expr::zero(),
                AB::Expr::zero(),
                local.is_real.into(),
                local.address_operation,
            ),
        );

        // Step 2. Write at the memory address and check page prot access.
        builder.eval_memory_access_write(
            clk_high.clone(),
            clk_low.clone() + AB::Expr::from_canonical_u32(MemoryAccessPosition::Memory as u32),
            &aligned_addr.clone().map(Into::into),
            local.memory_access,
            *local.adapter.prev_a(),
            local.is_real,
        );

        // Constrain the state of the CPU.
        <CPUState<AB::F> as SP1Operation<AB>>::eval(
            builder,
            CPUStateInput::new(
                local.state,
                [
                    local.state.pc[0] + AB::F::from_canonical_u32(PC_INC),
                    local.state.pc[1].into(),
                    local.state.pc[2].into(),
                ],
                AB::Expr::from_canonical_u32(CLK_INC),
                local.is_real.into(),
            ),
        );

        // Constrain the program and register reads.
        <ITypeReaderImmutable as SP1Operation<AB>>::eval(
            builder,
            ITypeReaderImmutableInput::new(
                clk_high,
                clk_low,
                local.state.pc,
                opcode,
                [instr_type, base_opcode, funct3, funct7],
                local.adapter,
                local.is_real.into(),
            ),
        );
    }
}
