use core::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, MaybeUninit},
};
use std::marker::PhantomData;

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
use sp1_hypercube::{air::MachineAir, Word};
use struct_reflection::{StructReflection, StructReflectionHelper};

use crate::{
    adapter::{
        register::r_type::{RTypeReader, RTypeReaderInput},
        state::{CPUState, CPUStateInput},
    },
    air::{SP1CoreAirBuilder, SP1Operation},
    eval_untrusted_program,
    operations::{SubwOperation, SubwOperationInput},
    utils::next_multiple_of_32,
    SupervisorMode, TrustMode, UserMode,
};

/// The number of main trace columns for `SubwChip` in Supervisor mode.
pub const NUM_SUBW_COLS_SUPERVISOR: usize = size_of::<SubwCols<u8, SupervisorMode>>();
/// The number of main trace columns for `SubwChip` in User mode.
pub const NUM_SUBW_COLS_USER: usize = size_of::<SubwCols<u8, UserMode>>();

/// A chip that implements subtraction for the opcode SUBW.
#[derive(Default)]
pub struct SubwChip<M: TrustMode> {
    pub _phantom: PhantomData<M>,
}

/// The column layout for the chip.
#[derive(AlignedBorrow, StructReflection, Default, Clone, Copy)]
#[repr(C)]
pub struct SubwCols<T, M: TrustMode> {
    /// The current shard, timestamp, program counter of the CPU.
    pub state: CPUState<T>,

    /// The adapter to read program and register information.
    pub adapter: RTypeReader<T>,

    /// Instance of `SubwOperation` to handle subtraction logic in `SubChip`'s ALU operations.
    pub subw_operation: SubwOperation<T>,

    /// Boolean to indicate whether the row is not a padding row.
    pub is_real: T,

    /// Adapter columns for trust mode specific data.
    pub adapter_cols: M::AdapterCols<T>,
}

impl<F: PrimeField32, M: TrustMode> MachineAir<F> for SubwChip<M> {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        if M::IS_TRUSTED {
            "Subw"
        } else {
            "SubwUser"
        }
    }

    fn column_names(&self) -> Vec<String> {
        SubwCols::<F, M>::struct_reflection().unwrap()
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return Some(0);
        }
        let nb_rows =
            next_multiple_of_32(input.subw_events.len(), input.fixed_log2_rows::<F, _>(self));
        Some(nb_rows)
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

        // Generate the rows for the trace.
        let chunk_size = std::cmp::max(input.subw_events.len() / num_cpus::get(), 1);
        let padded_nb_rows = <SubwChip<M> as MachineAir<F>>::num_rows(self, input).unwrap();
        let num_event_rows = input.subw_events.len();
        let width = <SubwChip<M> as BaseAir<F>>::width(self);

        unsafe {
            let padding_start = num_event_rows * width;
            let padding_size = (padded_nb_rows - num_event_rows) * width;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe { core::slice::from_raw_parts_mut(buffer_ptr, num_event_rows * width) };

        values.chunks_mut(chunk_size * width).enumerate().par_bridge().for_each(|(i, rows)| {
            rows.chunks_mut(width).enumerate().for_each(|(j, row)| {
                let idx = i * chunk_size + j;
                let cols: &mut SubwCols<F, M> = row.borrow_mut();

                if idx < input.subw_events.len() {
                    let mut byte_lookup_events = Vec::new();
                    let event = input.subw_events[idx];
                    self.event_to_row(&event.0, cols, &mut byte_lookup_events);
                    cols.state.populate(&mut byte_lookup_events, event.0.clk, event.0.pc);
                    cols.adapter.populate(&mut byte_lookup_events, event.1);
                    if !M::IS_TRUSTED {
                        let cols: &mut SubwCols<F, UserMode> = row.borrow_mut();
                        cols.adapter_cols.is_trusted = F::from_bool(!event.1.is_untrusted);
                    }
                }
            });
        });
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return;
        }

        let chunk_size = std::cmp::max(input.subw_events.len() / num_cpus::get(), 1);
        let event_iter = input.subw_events.chunks(chunk_size);
        let width = <SubwChip<M> as BaseAir<F>>::width(self);

        let blu_batches = event_iter
            .par_bridge()
            .map(|events| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|event| {
                    let mut row = vec![F::zero(); width];
                    let cols: &mut SubwCols<F, M> = row.as_mut_slice().borrow_mut();
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
            !shard.subw_events.is_empty()
                && (M::IS_TRUSTED != shard.program.enable_untrusted_programs)
        }
    }
}

impl<M: TrustMode> SubwChip<M> {
    /// Create a row from an event.
    fn event_to_row<F: PrimeField>(
        &self,
        event: &AluEvent,
        cols: &mut SubwCols<F, M>,
        blu: &mut impl ByteRecord,
    ) {
        cols.is_real = F::one();
        cols.subw_operation.populate(blu, event.b, event.c);
    }
}

impl<F, M: TrustMode> BaseAir<F> for SubwChip<M> {
    fn width(&self) -> usize {
        if M::IS_TRUSTED {
            NUM_SUBW_COLS_SUPERVISOR
        } else {
            NUM_SUBW_COLS_USER
        }
    }
}

impl<AB, M> Air<AB> for SubwChip<M>
where
    AB: SP1CoreAirBuilder,
    M: TrustMode,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &SubwCols<AB::Var, M> = (*local).borrow();

        builder.assert_bool(local.is_real);

        let opcode = AB::Expr::from_f(Opcode::SUBW.as_field());
        let funct3 = AB::Expr::from_canonical_u8(Opcode::SUBW.funct3().unwrap());
        let funct7 = AB::Expr::from_canonical_u8(Opcode::SUBW.funct7().unwrap());
        let base_opcode = AB::Expr::from_canonical_u32(Opcode::SUBW.base_opcode().0);
        let instr_type = AB::Expr::from_canonical_u32(Opcode::SUBW.instruction_type().0 as u32);

        // This chip is for the case `rd != x0`.
        builder.assert_zero(local.adapter.op_a_0);

        // Constrain the sub operation over `op_b` and `op_c`.
        <SubwOperation<AB::F> as SP1Operation<AB>>::eval(
            builder,
            SubwOperationInput::new(
                *local.adapter.b(),
                *local.adapter.c(),
                local.subw_operation,
                local.is_real.into(),
            ),
        );

        // Constrain the state of the CPU.
        // The program counter and timestamp increment by `4` and `8`.
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

        let u16_max = AB::F::from_canonical_u32((1 << 16) - 1);

        let word: Word<AB::Expr> = Word([
            local.subw_operation.value[0].into(),
            local.subw_operation.value[1].into(),
            local.subw_operation.msb.msb * u16_max,
            local.subw_operation.msb.msb * u16_max,
        ]);

        let mut is_trusted: AB::Expr = local.is_real.into();

        #[cfg(feature = "mprotect")]
        builder.assert_eq(
            builder.extract_public_values().is_untrusted_programs_enabled,
            AB::Expr::from_bool(!M::IS_TRUSTED),
        );

        if !M::IS_TRUSTED {
            let local = main.row_slice(0);
            let local: &SubwCols<AB::Var, UserMode> = (*local).borrow();

            let instruction = local.adapter.instruction::<AB>(opcode.clone());

            #[cfg(not(feature = "mprotect"))]
            builder.assert_zero(local.is_real);

            eval_untrusted_program(
                builder,
                local.state.pc,
                instruction,
                [instr_type, base_opcode, funct3, funct7],
                [local.state.clk_high::<AB>(), local.state.clk_low::<AB>()],
                local.is_real.into(),
                local.adapter_cols,
            );

            is_trusted = local.adapter_cols.is_trusted.into();
        }

        // Constrain the program and register reads.
        <RTypeReader<AB::F> as SP1Operation<AB>>::eval(
            builder,
            RTypeReaderInput::new(
                local.state.clk_high::<AB>(),
                local.state.clk_low::<AB>(),
                local.state.pc,
                opcode,
                word,
                local.adapter,
                local.is_real.into(),
                is_trusted,
            ),
        );
    }
}
