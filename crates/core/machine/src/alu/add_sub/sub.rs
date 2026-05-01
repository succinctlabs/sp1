use core::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, MaybeUninit},
};

use hashbrown::HashMap;
use itertools::Itertools;
use slop_air::{Air, BaseAir};
use slop_algebra::{AbstractField, PrimeField, PrimeField32};
use slop_matrix::Matrix;
use slop_maybe_rayon::prelude::{ParallelBridge, ParallelIterator};
use sp1_core_executor::{
    events::{AluEvent, ByteLookupEvent, ByteRecord},
    ExecutionRecord, Opcode, Program, CLK_INC, PC_INC,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::air::MachineAir;
use struct_reflection::{StructReflection, StructReflectionHelper};

use crate::{
    adapter::{
        register::r_type::{RTypeReader, RTypeReaderInput},
        state::{CPUState, CPUStateInput},
    },
    air::{SP1CoreAirBuilder, SP1Operation},
    operations::{SubOperation, SubOperationInput},
    utils::next_multiple_of_32,
};

/// The number of main trace columns for `SubChip`.
pub const NUM_SUB_COLS: usize = size_of::<SubCols<u8>>();

/// A chip that implements subtraction for the opcode SUB.
#[derive(Default)]
pub struct SubChip;

/// The column layout for the chip.
#[derive(AlignedBorrow, StructReflection, Default, Clone, Copy)]
#[repr(C)]
pub struct SubCols<T> {
    /// The current shard, timestamp, program counter of the CPU.
    pub state: CPUState<T>,

    /// The adapter to read program and register information.
    pub adapter: RTypeReader<T>,

    /// Instance of `SubOperation` to handle subtraction logic in `SubChip`'s ALU operations.
    pub sub_operation: SubOperation<T>,

    /// Boolean to indicate whether the row is not a padding row.
    pub is_real: T,
}

impl<F: PrimeField32> MachineAir<F> for SubChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        "Sub"
    }

    fn column_names(&self) -> Vec<String> {
        SubCols::<F>::struct_reflection().unwrap()
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows =
            next_multiple_of_32(input.sub_events.len(), input.fixed_log2_rows::<F, _>(self));
        Some(nb_rows)
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        // Generate the rows for the trace.
        let chunk_size = std::cmp::max(input.sub_events.len() / num_cpus::get(), 1);
        let padded_nb_rows = <SubChip as MachineAir<F>>::num_rows(self, input).unwrap();

        let num_event_rows = input.sub_events.len();

        unsafe {
            let padding_start = num_event_rows * NUM_SUB_COLS;
            let padding_size = (padded_nb_rows - num_event_rows) * NUM_SUB_COLS;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values =
            unsafe { core::slice::from_raw_parts_mut(buffer_ptr, num_event_rows * NUM_SUB_COLS) };

        values.chunks_mut(chunk_size * NUM_SUB_COLS).enumerate().par_bridge().for_each(
            |(i, rows)| {
                rows.chunks_mut(NUM_SUB_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut SubCols<F> = row.borrow_mut();

                    if idx < input.sub_events.len() {
                        let mut byte_lookup_events = Vec::new();
                        let event = input.sub_events[idx];
                        self.event_to_row(&event.0, cols, &mut byte_lookup_events);
                        cols.state.populate(&mut byte_lookup_events, event.0.clk, event.0.pc);
                        cols.adapter.populate(&mut byte_lookup_events, event.1);
                    }
                });
            },
        );
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        let chunk_size = std::cmp::max(input.sub_events.len() / num_cpus::get(), 1);

        let event_iter = input.sub_events.chunks(chunk_size);

        let blu_batches = event_iter
            .par_bridge()
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|event| {
                    let mut row = [F::zero(); NUM_SUB_COLS];
                    let cols: &mut SubCols<F> = row.as_mut_slice().borrow_mut();
                    self.event_to_row(&event.0, cols, &mut blu);
                    cols.state.populate(&mut blu, event.0.clk, event.0.pc);
                    cols.adapter.populate(&mut blu, event.1);
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
            !shard.sub_events.is_empty()
        }
    }
}

impl SubChip {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField>(
        &self,
        event: &AluEvent,
        cols: &mut SubCols<F>,
        blu: &mut impl ByteRecord,
    ) {
        cols.is_real = F::one();
        cols.sub_operation.populate(blu, event.b, event.c);
    }
}

impl<F> BaseAir<F> for SubChip {
    fn width(&self) -> usize {
        NUM_SUB_COLS
    }
}

impl<AB> Air<AB> for SubChip
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &SubCols<AB::Var> = (*local).borrow();

        builder.assert_bool(local.is_real);

        let opcode = AB::Expr::from_f(Opcode::SUB.as_field());
        let funct3 = AB::Expr::from_canonical_u8(Opcode::SUB.funct3().unwrap());
        let funct7 = AB::Expr::from_canonical_u8(Opcode::SUB.funct7().unwrap());
        let base_opcode = AB::Expr::from_canonical_u32(Opcode::SUB.base_opcode().0);
        let instr_type = AB::Expr::from_canonical_u32(Opcode::SUB.instruction_type().0 as u32);

        // This chip is for the case `rd != x0`.
        builder.assert_zero(local.adapter.op_a_0);

        // Constrain the sub operation over `op_b` and `op_c`.
        let op_input = SubOperationInput::<AB>::new(
            *local.adapter.b(),
            *local.adapter.c(),
            local.sub_operation,
            local.is_real.into(),
        );
        <SubOperation<AB::F> as SP1Operation<AB>>::eval(builder, op_input);

        // Constrain the state of the CPU.
        // The program counter and timestamp increment by `4` and `8`.
        <CPUState<AB::F> as SP1Operation<AB>>::eval(
            builder,
            CPUStateInput {
                cols: local.state,
                next_pc: [
                    local.state.pc[0] + AB::F::from_canonical_u32(PC_INC),
                    local.state.pc[1].into(),
                    local.state.pc[2].into(),
                ],
                clk_increment: AB::Expr::from_canonical_u32(CLK_INC),
                is_real: local.is_real.into(),
            },
        );

        // Constrain the program and register reads.
        <RTypeReader<AB::F> as SP1Operation<AB>>::eval(
            builder,
            RTypeReaderInput {
                clk_high: local.state.clk_high::<AB>(),
                clk_low: local.state.clk_low::<AB>(),
                pc: local.state.pc,
                opcode,
                op_a_write_value: local.sub_operation.value.map(|x| x.into()),
                instr_field_consts: [instr_type, base_opcode, funct3, funct7],
                cols: local.adapter,
                is_real: local.is_real.into(),
            },
        );
    }
}
